"""Blue-team simulation.

observe()   - what the SOC can actually see, given the telemetry profile (gaps are applied here)
run_blue()  - apply detection rules, then simulate alert -> triage -> containment

SOC timings (detection latency, triage delay, containment propagation) are SIMULATED values drawn
from fixed ranges with a per-test seed. They illustrate the measurement framework; they are not
measurements of any real SOC.
"""
import random
from datetime import timedelta

from config import (SEED, RULES, BRAND_TOKEN, APPROVED_BRAND_DOMAINS, APPROVED_AUTH_ORIGINS,
                    FIRST_SEEN_DAYS, YOUNG_HOP_DAYS, ANALYSTS)
from scenarios import TRUSTED_CATEGORIES


def observe(truth_events, profile):
    """Apply telemetry gaps from the profile. Returns a new list of events (copies)."""
    out = []
    for e in truth_events:
        key = (e["scenario_code"], e["event_type"], e["hop_number"] or 0)
        if key in profile["dropped_events"]:
            continue
        e2 = dict(e, metadata=dict(e["metadata"]))
        if e["event_type"] == "CLICK" and e["scenario_code"] in profile["unlinked_click_scenarios"]:
            e2["metadata"]["impression_id"] = None
        out.append(e2)
    return out


def _age(domain, reg):
    return reg.get(domain, {}).get("age_days", 9999)


def _trusted(domain, reg):
    return reg.get(domain, {}).get("category") in TRUSTED_CATEGORIES


def find_hits(evs, profile, intel, reg):
    """Return a list of rule hits for one test's observed events."""
    enabled = profile["enabled_rules"]
    approved = APPROVED_BRAND_DOMAINS
    tokens = profile["allowlist_tokens"]
    hops = sorted([e for e in evs if e["event_type"] == "REDIRECT"], key=lambda e: e["hop_number"])
    landing = [e for e in evs if e["event_type"] == "LANDING"]

    cands, seen = [], set()
    if profile["evaluate_final_destination"]:
        for e in hops + landing:
            if e["domain"] not in seen:
                seen.add(e["domain"])
                cands.append((e["domain"], e["timestamp"]))
    elif hops:
        cands.append((hops[0]["domain"], hops[0]["timestamp"]))

    hits = []
    for dom, ts in cands:
        if "R1" in enabled and dom in intel:
            hits.append(dict(rule="R1", domain=dom, trigger_ts=ts, detail="domain in threat-intel table"))
        if "R2" in enabled and _age(dom, reg) < FIRST_SEEN_DAYS and not _trusted(dom, reg) and dom not in approved:
            hits.append(dict(rule="R2", domain=dom, trigger_ts=ts,
                             detail=f"domain age {_age(dom, reg)} days (< {FIRST_SEEN_DAYS})"))
        if "R3" in enabled and BRAND_TOKEN in dom and dom not in approved and not any(tok in dom for tok in tokens):
            hits.append(dict(rule="R3", domain=dom, trigger_ts=ts,
                             detail=f"contains brand token '{BRAND_TOKEN}', not an approved domain"))
    if "R4" in enabled and len(hops) >= 2:
        young = [h["domain"] for h in hops[:-1] if _age(h["domain"], reg) < YOUNG_HOP_DAYS and not _trusted(h["domain"], reg)]
        if young:
            hits.append(dict(rule="R4", domain=young[0], trigger_ts=hops[-1]["timestamp"],
                             detail=f"{len(hops)} hops via young intermediate host {young[0]}"))
    if "R5" in enabled:
        for e in evs:
            if e["event_type"] == "CREDENTIAL_ENTRY" and e["domain"] not in APPROVED_AUTH_ORIGINS:
                hits.append(dict(rule="R5", domain=e["domain"], trigger_ts=e["timestamp"],
                                 detail="credential-entry test event on non-approved origin"))
    if "R6" in enabled:
        click = [e for e in evs if e["event_type"] == "CLICK"]
        for e in evs:
            if e["event_type"] == "DOWNLOAD" and click and click[0]["timestamp"] < e["timestamp"]:
                hits.append(dict(rule="R6", domain=e["domain"], trigger_ts=e["timestamp"],
                                 detail="download after ad click", url=e["url"]))
    return hits


def run_blue(tests, observed, profile, intel, reg):
    """Returns (events_all, per_test) where per_test[test_id] holds hits/alert/incident/containment."""
    by_test = {}
    for e in observed:
        by_test.setdefault(e["test_id"], []).append(e)

    blue_events, per_test = [], {}
    alert_n = inc_n = cont_n = 0

    for idx, t in enumerate(tests):
        tid = t["test_id"]
        evs = by_test.get(tid, [])
        rng = random.Random(SEED * 1000 + idx)
        lat = {r: rng.randint(*RULES[r]["latency"]) for r in sorted(RULES)}
        d_alert = rng.randint(1, 5)
        d_triage = rng.randint(20, 150)
        d_triage_len = rng.randint(60, 240)
        d_req = rng.randint(5, 45)
        d_prop = rng.randint(20, 120)
        analyst = ANALYSTS[idx % len(ANALYSTS)]

        info = dict(hits=[], primary=None, detected=False, inline_blocked=False, alert=None, incident=None,
                    containment=None, legit_blocked=False)
        per_test[tid] = info
        hits = find_hits(evs, profile, intel, reg)
        if not hits:
            continue

        for h in hits:
            h["detection_ts"] = h["trigger_ts"] + timedelta(seconds=lat[h["rule"]])
        hits.sort(key=lambda h: h["detection_ts"])
        primary = hits[0]
        rule = RULES[primary["rule"]]
        det_ts = primary["detection_ts"]

        if rule["inline"]:
            # Inline block: anything after the detection never happens
            before = len(evs)
            evs[:] = [e for e in evs if not (e["event_type"] in ("LANDING", "CREDENTIAL_ENTRY", "DOWNLOAD")
                                              and e["timestamp"] > det_ts)]
            info["inline_blocked"] = len(evs) < before
            by_test[tid] = evs
            hits = [h for h in hits if h["trigger_ts"] <= det_ts]

        info.update(hits=hits, primary=primary, detected=True)
        sev = rule["severity"]
        blue_events.append(dict(test_id=tid, timestamp=det_ts, event_type="DETECTION", source="blue_team",
                                domain=primary["domain"], url=None, hop_number=None, http_status=None,
                                severity=sev, rule=f"{primary['rule']}:{rule['name']}", status="observed",
                                data_origin="synthetic",
                                metadata=dict(detail=primary["detail"],
                                              all_rules=[h["rule"] for h in hits],
                                              domain_age_days=_age(primary["domain"], reg))))

        alert_n += 1
        alert_id = f"ALERT-{alert_n:03d}"
        # An inline block raises its alert at the moment of detection; other rules add a small alerting delay.
        alert_ts = det_ts if rule["inline"] else det_ts + timedelta(seconds=d_alert)
        info["alert"] = dict(alert_id=alert_id, test_id=tid, created_at=alert_ts, severity=sev,
                             detection_type=rule["name"], source="POC-DetectionEngine", status="Open",
                             assigned_team="SOC", rule=primary["rule"])
        blue_events.append(dict(test_id=tid, timestamp=alert_ts, event_type="ALERT", source="blue_team",
                                domain=primary["domain"], url=None, hop_number=None, http_status=None,
                                severity=sev, rule=primary["rule"], status="observed", data_origin="synthetic",
                                metadata=dict(alert_id=alert_id)))

        tri_start = alert_ts + timedelta(seconds=d_triage)
        tri_end = tri_start + timedelta(seconds=d_triage_len)
        inc_n += 1
        verdict = "False Positive" if t["benign"] else "Confirmed"
        info["incident"] = dict(incident_id=f"INC-{inc_n:03d}", alert_id=alert_id, test_id=tid,
                                triage_started_at=tri_start, analyst_id=analyst,
                                investigation_status=verdict,
                                correlated_events=len([e for e in evs if e["test_id"] == tid]),
                                triage_completed_at=tri_end)
        info["alert"]["status"] = "Closed - false positive" if t["benign"] else "Confirmed"
        for et, ts in (("TRIAGE_START", tri_start), ("TRIAGE_END", tri_end)):
            blue_events.append(dict(test_id=tid, timestamp=ts, event_type=et, source="blue_team",
                                    domain=None, url=None, hop_number=None, http_status=None, severity=None,
                                    rule=None, status="observed", data_origin="synthetic",
                                    metadata=dict(incident_id=info["incident"]["incident_id"],
                                                  analyst_id=analyst, verdict=verdict)))

        # Containment
        if rule["inline"]:
            req_ts, eff_ts = det_ts, det_ts + timedelta(seconds=1)
            mode = "inline_block"
        elif rule["auto_contain"]:
            req_ts = alert_ts + timedelta(seconds=10)
            eff_ts = req_ts + timedelta(seconds=d_prop)
            mode = "automated"
        else:
            req_ts = tri_end + timedelta(seconds=d_req)
            eff_ts = req_ts + timedelta(seconds=d_prop)
            mode = "analyst_requested"
        action = rule["action"]
        target = primary.get("url") if action == "URL_block" and primary.get("url") else primary["domain"]
        cont_n += 1
        failed = t["scenario_code"] in profile["failed_containment_scenarios"]
        info["containment"] = dict(containment_id=f"CONT-{cont_n:03d}", incident_id=info["incident"]["incident_id"],
                                   test_id=tid, action=action, requested_at=req_ts,
                                   completed_at=None if failed else eff_ts,
                                   status="Failed" if failed else "Success", target=target, mode=mode)
        blue_events.append(dict(test_id=tid, timestamp=req_ts, event_type="CONTAINMENT_REQUEST", source="blue_team",
                                domain=primary["domain"], url=None, hop_number=None, http_status=None,
                                severity=None, rule=None, status="observed", data_origin="synthetic",
                                metadata=dict(containment_id=info["containment"]["containment_id"],
                                              action=action, target=target, mode=mode)))
        if failed:
            blue_events.append(dict(test_id=tid, timestamp=req_ts + timedelta(seconds=90),
                                    event_type="CONTAINMENT_FAILED", source="blue_team", domain=primary["domain"],
                                    url=None, hop_number=None, http_status=None, severity="High", rule=None,
                                    status="observed", data_origin="synthetic",
                                    metadata=dict(reason="Block did not propagate to the enforcement point",
                                                  containment_id=info["containment"]["containment_id"])))
        else:
            blue_events.append(dict(test_id=tid, timestamp=eff_ts, event_type="CONTAINMENT_EFFECTIVE",
                                    source="blue_team", domain=primary["domain"], url=None, hop_number=None,
                                    http_status=None, severity=None, rule=None, status="observed",
                                    data_origin="synthetic",
                                    metadata=dict(containment_id=info["containment"]["containment_id"],
                                                  action=action, target=target)))
            info["legit_blocked"] = bool(t["benign"])

    code_of = {t["test_id"]: t["scenario_code"] for t in tests}
    for e in blue_events:
        e["scenario_code"] = code_of[e["test_id"]]
    all_events = [e for evs in by_test.values() for e in evs] + blue_events
    return all_events, per_test

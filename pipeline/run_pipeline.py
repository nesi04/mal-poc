"""Run the full pipeline:  generate -> observe -> detect -> metrics -> export JSON/CSV.

Usage:  python run_pipeline.py
Outputs: ../public/data/*.json (for the React app) and ./out/csv/*.csv
Optional public data: put a Kaggle malicious-URLs file in ./data/public/malicious_urls.csv
  (columns url,type  or the PhiUSIIL layout URL,label).
"""
import csv
import json
import os
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

from config import PROFILES, RULES, SEED, PLATFORM_LABEL, VARIANTS
from generate import build_truth
from detect import observe, run_blue
from metrics import (evaluate, stages, compute_metrics, DEFINITIONS, build_findings, build_retest,
                     SEVERITY_METHOD, EVIDENCE_ITEMS, _s)
from scenarios import SCENARIOS
from chokepoints import build as build_chokepoints

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_JSON = os.path.join(HERE, "..", "public", "data")
OUT_CSV = os.path.join(HERE, "out", "csv")
PUBLIC_CSV = os.path.join(HERE, "data", "public", "malicious_urls.csv")
PUBLIC_LIMIT = 500


def load_public_intel(limit=PUBLIC_LIMIT):
    """Hostnames of phishing/malware rows from an optional public file. Returns (hosts, info)."""
    info = dict(loaded=False, file="pipeline/data/public/malicious_urls.csv", schema=None, rows_read=0,
                class_counts={}, hostnames_used=0, hostname_limit=limit, notes=[])
    if not os.path.exists(PUBLIC_CSV):
        info["notes"].append("File not found. Only synthetic threat-intel entries are used.")
        return set(), info
    hosts, counts, rows = set(), Counter(), 0
    with open(PUBLIC_CSV, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        cols = {c.strip().lower(): c for c in (reader.fieldnames or [])}
        url_col, type_col, label_col = cols.get("url"), cols.get("type"), cols.get("label")
        if not url_col or not (type_col or label_col):
            info["notes"].append("Columns not recognised. Expected url + type, or URL + label.")
            return set(), info
        info["schema"] = "url,type" if type_col else "URL,label (PhiUSIIL: 1 = legitimate, 0 = phishing)"
        for row in reader:
            rows += 1
            if type_col:
                cls = (row.get(type_col) or "").strip().lower()
                bad = cls in ("phishing", "malware")
            else:
                lab = (row.get(label_col) or "").strip()
                cls = "legitimate" if lab == "1" else "phishing"
                bad = lab == "0"
            counts[cls] += 1
            if bad and len(hosts) < limit:
                raw = row.get(url_col) or ""
                host = urlparse(raw if "//" in raw else "//" + raw).hostname
                if host and "." in host:
                    hosts.add(host.lower())
    info.update(loaded=True, rows_read=rows, class_counts=dict(counts), hostnames_used=len(hosts))
    return hosts, info


def ser_event(e, eid):
    return dict(event_id=eid, test_id=e["test_id"], scenario_code=e["scenario_code"],
                timestamp=_s(e["timestamp"]), event_type=e["event_type"], source=e["source"],
                domain=e["domain"], url=e["url"], hop_number=e["hop_number"], http_status=e["http_status"],
                severity=e["severity"], rule=e["rule"], status=e["status"], data_origin=e["data_origin"],
                metadata=e["metadata"])


def write_csv(name, rows):
    os.makedirs(OUT_CSV, exist_ok=True)
    if not rows:
        return
    keys = list(rows[0].keys())
    with open(os.path.join(OUT_CSV, name), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow({k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in r.items()})


def main():
    os.makedirs(OUT_JSON, exist_ok=True)
    public_hosts, public_info = load_public_intel()

    tests, truth, registry, known_bad = build_truth()
    intel = set(known_bad) | public_hosts
    result = {}
    for run_id, profile in PROFILES.items():
        observed = observe(truth, profile)
        all_events, per_test = run_blue(tests, observed, profile, intel, registry)
        rows = evaluate(tests, truth, all_events, per_test)
        all_events.sort(key=lambda e: (e["timestamp"], e["test_id"]))
        ser = [ser_event(e, f"EVT-{i + 1:05d}") for i, e in enumerate(all_events)]
        by_test = {}
        for e in ser:
            by_test.setdefault(e["test_id"], []).append(e)
        for r in rows:
            r["stages"] = stages(r, all_events)
            r["event_count"] = len(by_test.get(r["test_id"], []))
        result[run_id] = dict(rows=rows, events=ser, by_test=by_test, metrics=compute_metrics(rows), per_test=per_test)

    base, retest = result["baseline"], result["retest"]
    findings = build_findings(base["rows"], retest["rows"])
    retest_cmp = build_retest(base["rows"], retest["rows"], findings)
    choke = build_chokepoints(tests, result, registry)

    def dump(name, obj):
        big = name in ("journeys.json", "test_cases.json")   # keep the large files compact
        with open(os.path.join(OUT_JSON, name), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=None if big else 1, separators=(",", ":") if big else None)

    labels = ["POC", "SIMULATED", "SYNTHETIC DATA", "AUTHORIZED TESTING"]
    if public_info["loaded"]:
        labels.insert(2, "PUBLIC DATA")
    dump("meta.json", dict(
        title="Malvertising Security POC", subtitle="Authorized testing simulation",
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), seed=SEED,
        labels=labels, journeys=len(tests), scenarios=len(SCENARIOS), variants=VARIANTS,
        data_origin_legend=dict(
            synthetic="Generated by this POC. Not real telemetry.",
            public="Taken from a public dataset (only if malicious_urls.csv was supplied).",
            calculated="Computed by the metrics engine from the tables above."),
        runs={k: dict(label=v["label"], description=v["description"]) for k, v in PROFILES.items()},
        assumptions=["No Microsoft Sentinel, Bing or Microsoft production telemetry is used.",
                     "All journey domains are reserved .test names; IPs are RFC 5737 documentation ranges.",
                     "TTD starts at the first redirect hop; TTC starts at alert creation.",
                     "Detection latency, triage delay and containment propagation are SIMULATED.",
                     "Synthetic credential and download events only; no secret or malware is involved."],
        public_intel_rows=public_info["hostnames_used"], evidence_items=EVIDENCE_ITEMS,
        rules=[dict(id=k, name=v["name"], severity=v["severity"], description=v["desc"]) for k, v in RULES.items()],
        severity_method=SEVERITY_METHOD))

    dump("metrics.json", dict(
        definitions=DEFINITIONS,
        runs={k: dict(kpis=v["metrics"],
                      per_test=[dict(test_id=r["test_id"], scenario_code=r["scenario_code"], variant=r["variant"],
                                     ttd_s=r["ttd_s"], ttt_s=r["ttt_s"], ttc_s=r["ttc_s"],
                                     propagation_s=r["propagation_s"]) for r in v["rows"]])
              for k, v in result.items()}))

    strip = lambda rows: [{k: v for k, v in r.items() if k != "stages"} for r in rows]
    dump("test_cases.json", {k: strip(v["rows"]) for k, v in result.items()})
    dump("journeys.json", {k: {r["test_id"]: dict(stages=r["stages"], events=v["by_test"].get(r["test_id"], []),
                                                  evidence=r["evidence"]) for r in v["rows"]}
                           for k, v in result.items()})
    dump("findings.json", dict(severity_method=SEVERITY_METHOD, findings=findings))
    dump("retest.json", retest_cmp)
    dump("chokepoints.json", choke)

    # Scenario catalog (one row per scenario, with its variant test ids)
    catalog = []
    for i, s in enumerate(SCENARIOS):
        mine = [t for t in tests if t["scenario_code"] == s["code"]]
        catalog.append(dict(
            scenario_code=s["code"], scenario_name=s["name"], campaign_id=f"CAMP-{i + 1:03d}",
            campaign_type=s["campaign_type"], keyword_class=s["keyword_class"], ad_title=s["ad_title"],
            platform=PLATFORM_LABEL, display_domain=s["display_domain"], final_domain=mine[0]["hops"][-1],
            display_final_mismatch=s["display_domain"] != mine[0]["hops"][-1],
            hops_min=min(t["expected_hops"] for t in mine), hops_max=max(t["expected_hops"] for t in mine),
            variants=len(mine), test_ids=[t["test_id"] for t in mine],
            expected_detection=not s["benign"], expected_containment=not s["benign"],
            pattern=s["pattern"], intended_signal=s["intended_signal"], cloaking=s["cloaking"],
            credential_test=s["credential"], download_test=s["download"], benign=s["benign"],
            data_origin="synthetic"))
    dump("scenarios.json", catalog)

    # Red team and Blue team summary views
    cnt = Counter(e["event_type"] for e in truth)
    red = dict(
        scenarios=len(SCENARIOS), journeys=len(tests), variants_per_scenario=VARIANTS,
        campaigns=len({t["campaign_id"] for t in tests}), ads=len({t["ad_id"] for t in tests}),
        impressions=cnt["IMPRESSION"], clicks=cnt["CLICK"], redirect_hops=cnt["REDIRECT"], landings=cnt["LANDING"],
        credential_tests=cnt["CREDENTIAL_ENTRY"], download_tests=cnt["DOWNLOAD"],
        expected_detections=sum(1 for t in tests if t["expected_detection"]),
        expected_containments=sum(1 for t in tests if t["expected_containment"]),
        benign_controls=sum(1 for t in tests if t["benign"]),
        note="Counts are what the red team planned and executed, before any defensive action.")
    blue = {}
    for run_id, v in result.items():
        rows = v["rows"]
        blue[run_id] = dict(
            alerts=[dict(alert_id=r["alert"]["alert_id"], test_id=r["test_id"], scenario_code=r["scenario_code"],
                         variant=r["variant"], severity=r["alert"]["severity"], detection_type=r["alert"]["detection_type"],
                         status=r["alert"]["status"], created_at=r["alert"]["created_at"],
                         investigation=(r["incident"] or {}).get("investigation_status"),
                         containment=(r["containment"] or {}).get("status")) for r in rows if r["alert"]],
            undetected=[r["test_id"] for r in rows if r["expected_detection"] and not r["actual_detection"]],
            false_positives=[r["test_id"] for r in rows if r["benign"] and r["actual_detection"]],
            containment_failed=[r["test_id"] for r in rows if "CONTAINMENT_FAILED" in r["gaps"]],
            open_findings=sum(1 for f in findings if (run_id == "baseline" or f["status"] != "Remediated (POC scenario)")),
            findings_total=len(findings))
    dump("views.json", dict(red=red, blue=blue))

    # Public data status + lookup list
    dump("data_sources.json", dict(
        public=public_info, synthetic_intel=sorted(known_bad),
        sample_defanged=[h.replace(".", "[.]") for h in sorted(public_hosts)[:10]],
        intel_total=len(intel), intel_synthetic=len(known_bad), intel_public=len(public_hosts),
        journey_domains=len(registry),
        note="Journey domains are reserved .test names, so no journey matches a public hostname by design. "
             "Public hostnames only extend the known-bad lookup used by rule R1."))
    dump("intel_public.json", sorted(public_hosts))

    # CSV exports
    for run_id, v in result.items():
        write_csv(f"events_{run_id}.csv", v["events"])
        write_csv(f"test_cases_{run_id}.csv", [{k: x for k, x in r.items() if k not in ("stages", "evidence")} for r in v["rows"]])
        write_csv(f"alerts_{run_id}.csv", [r["alert"] for r in v["rows"] if r["alert"]])
        write_csv(f"incidents_{run_id}.csv", [r["incident"] for r in v["rows"] if r["incident"]])
        write_csv(f"containments_{run_id}.csv", [r["containment"] for r in v["rows"] if r["containment"]])
    write_csv("findings.csv", findings)

    # Console summary
    print(f"Journeys: {len(tests)} ({len(SCENARIOS)} scenarios x {VARIANTS} variants) | domains: {len(registry)}")
    print(f"Public intel: {'loaded, ' + str(len(public_hosts)) + ' hostnames from ' + str(public_info['rows_read']) + ' rows' if public_info['loaded'] else 'not loaded (optional)'}")
    for run_id in ("baseline", "retest"):
        m = result[run_id]["metrics"]
        print(f"\n=== {run_id.upper()} ===")
        print(f" Impression->Click   {m['impression_click_visibility']['value']}%  ({m['impression_click_visibility']['num']}/{m['impression_click_visibility']['den']})")
        cl = m["click_landing_visibility"]
        print(f" Click->Landing      {cl['value']}%  ({cl['num']}/{cl['den']}; inline-blocked {cl['blocked_inline']}, telemetry-missing {cl['missing_telemetry']})")
        print(f" Detection coverage  {m['detection_coverage']['value']}%  ({m['detection_coverage']['num']}/{m['detection_coverage']['den']})")
        print(f" TTD (s) {m['ttd']}\n TTT (s) {m['ttt']}\n TTC (s) {m['ttc']}\n Propagation (s) {m['blocking_propagation']}")
        print(f" Redirect inspection {m['redirect_inspection']['value']}%  ({m['redirect_inspection']['num']}/{m['redirect_inspection']['den']})")
        print(f" Containment success {m['containment_success']['value']}%  (failed {m['containment_success']['failed']})")
        fp = m["false_positive"]
        print(f" False positives     {fp['legitimate_with_incident']}/{fp['legitimate_tested']} benign flagged, {fp['legitimate_blocked']} blocked")
        print(f" Identity protection {m['identity_protection']['value']}%  ({m['identity_protection']['num']}/{m['identity_protection']['den']})")
        print(f" Evidence complete   {m['evidence_completeness']['value']}%  ({m['evidence_completeness']['num']}/{m['evidence_completeness']['den']})")
        print(f" Journey reconstruct {m['journey_reconstruction']['value']}%")
        print(f" Alerts {m['alerts']}  | Pass/Fail {m['totals']['pass_']}/{m['totals']['fail']}")
        by = {}
        for r in result[run_id]["rows"]:
            by.setdefault((r["scenario_code"], r["scenario_name"]), []).append(r)
        for (code, name), rs in by.items():
            gaps = Counter(g for r in rs for g in r["gaps"])
            print(f"   {code} {name:42} pass {sum(1 for r in rs if r['result'] == 'Pass')}/{len(rs)} gaps={dict(gaps)}")
    print("\nCHOKE POINTS (greedy curve):")
    for c in choke["curve"]:
        print(f"  step {c['step']}: {c['label']:38} +{len(c['newly_covered'])} -> {c['cumulative_pct']}% (collateral {c['collateral']})")
    print(f"\nFindings: {len(findings)}  (open: {sum(1 for f in findings if f['status'] == 'Open')}, partial: {sum(1 for f in findings if f['status'].startswith('Partially'))})")
    print("JSON written to", os.path.abspath(OUT_JSON))


if __name__ == "__main__":
    main()

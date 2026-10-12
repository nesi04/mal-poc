"""Metric engine. Everything here is CALCULATED from the (synthetic) event tables.

Definitions used consistently across all tests (also exported to metrics.json):
  attack event  = first REDIRECT hop of the journey (ground truth timestamp)
  TTD           = detection timestamp - attack event
  TTT           = triage start - alert creation
  TTC           = containment effective - alert creation
  propagation   = containment effective - containment requested
"""
import statistics

EVIDENCE_ITEMS = ["Campaign", "Advertisement", "Impression", "Click", "Redirect", "Landing",
                  "Detection", "Alert", "Investigation", "Containment"]


def _s(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _pct(num, den):
    return dict(value=round(100.0 * num / den, 1) if den else None, num=num, den=den)


def _stats(vals):
    if not vals:
        return dict(n=0, mean=None, median=None, min=None, max=None)
    return dict(n=len(vals), mean=round(statistics.mean(vals), 1), median=round(statistics.median(vals), 1),
                min=min(vals), max=max(vals))


def evaluate(tests, truth_events, all_events, per_test):
    """Build one result row per test with observed facts, gaps and evidence."""
    by_test, truth_by = {}, {}
    for e in all_events:
        by_test.setdefault(e["test_id"], []).append(e)
    for e in truth_events:
        truth_by.setdefault(e["test_id"], []).append(e)

    rows = []
    for t in tests:
        tid = t["test_id"]
        evs = sorted(by_test.get(tid, []), key=lambda e: e["timestamp"])
        truth = truth_by[tid]
        info = per_test[tid]
        of = lambda et: [e for e in evs if e["event_type"] == et]
        imp, clk, hops, land = of("IMPRESSION"), of("CLICK"), of("REDIRECT"), of("LANDING")
        truth_landing = [e for e in truth if e["event_type"] == "LANDING"]
        attack_ts = min(e["timestamp"] for e in truth if e["event_type"] == "REDIRECT")

        click_linked = bool(clk) and clk[0]["metadata"].get("impression_id") is not None
        landing_expected = bool(truth_landing) and not info["inline_blocked"]
        cont = info["containment"]
        contained = bool(cont) and cont["status"] == "Success"
        detected = info["detected"]

        gaps = []
        if len(hops) < t["expected_hops"]:
            gaps.append("REDIRECT_HOP_MISSING")
        if t["expected_detection"] and not detected:
            gaps.append("DETECTION_MISSED")
        if not t["expected_detection"] and detected:
            gaps.append("FALSE_POSITIVE")
        if t["expected_containment"] and detected and not contained:
            gaps.append("CONTAINMENT_FAILED")
        if clk and not click_linked:
            gaps.append("CLICK_NOT_CORRELATED")
        if landing_expected and not land:
            gaps.append("LANDING_NOT_LOGGED")

        # Evidence checklist: (expected, captured)
        ev_exp = dict(Campaign=True, Advertisement=True, Impression=True, Click=True, Redirect=True,
                      Landing=landing_expected, Detection=t["expected_detection"], Alert=t["expected_detection"],
                      Investigation=t["expected_detection"], Containment=t["expected_containment"])
        ev_cap = dict(Campaign=True, Advertisement=True, Impression=bool(imp), Click=bool(clk) and click_linked,
                      Redirect=len(hops) == t["expected_hops"], Landing=bool(land), Detection=bool(of("DETECTION")),
                      Alert=bool(of("ALERT")), Investigation=bool(of("TRIAGE_END")),
                      Containment=bool(of("CONTAINMENT_EFFECTIVE")))
        evidence = {k: dict(expected=ev_exp[k], captured=ev_cap[k] and True) for k in EVIDENCE_ITEMS}

        # Timings (seconds)
        inc, alert = info["incident"], info["alert"]
        ttd = (info["primary"]["detection_ts"] - attack_ts).total_seconds() if detected and t["expected_detection"] else None
        ttt = (inc["triage_started_at"] - alert["created_at"]).total_seconds() if inc else None
        ttc = ((cont["completed_at"] - alert["created_at"]).total_seconds()
               if contained and t["expected_containment"] else None)
        prop = ((cont["completed_at"] - cont["requested_at"]).total_seconds()
                if contained and t["expected_containment"] else None)

        result = "Pass" if not gaps else "Fail"
        rows.append(dict(
            test_id=tid, scenario_code=t["scenario_code"], scenario_name=t["scenario_name"], variant=t["variant"],
            campaign_id=t["campaign_id"], ad_id=t["ad_id"], platform=t["platform"],
            domain_profile=t["scenario"]["pattern"], benign=t["benign"], display_domain=t["display_domain"],
            hop_domains=t["hops"], infra=t["infra"],
            expected_detection=t["expected_detection"], expected_containment=t["expected_containment"],
            expected_redirect_hops=t["expected_hops"], logged_redirect_hops=len(hops),
            actual_detection=detected, actual_containment=contained,
            detection_rule=(f"{info['primary']['rule']}:{info['alert']['detection_type']}" if detected else None),
            rules_fired=[h["rule"] for h in info["hits"]],
            inline_blocked=info["inline_blocked"], landing_expected=landing_expected, landing_logged=bool(land),
            click_correlated=click_linked, legit_blocked=info["legit_blocked"],
            credential_event=any(e["event_type"] == "CREDENTIAL_ENTRY" for e in truth),
            credential_detected=any(h["rule"] == "R5" for h in info["hits"]),
            result=result, gaps=gaps, evidence=evidence,
            ttd_s=ttd, ttt_s=ttt, ttc_s=ttc, propagation_s=prop,
            alert=_ser(alert), incident=_ser(inc), containment=_ser(cont),
            data_origin="synthetic",
        ))
    return rows


def _ser(d):
    if not d:
        return None
    return {k: (_s(v) if hasattr(v, "strftime") else v) for k, v in d.items()}


def stages(row, events):
    """Ordered journey stages with status + evidence flag for the Journey Explorer."""
    evs = sorted([e for e in events if e["test_id"] == row["test_id"]], key=lambda e: e["timestamp"])
    first = lambda et: next((e for e in evs if e["event_type"] == et), None)
    out = []

    def add(stage, ev, expected=True, ok=None, detail=""):
        captured = ev is not None if ok is None else ok
        if expected and captured:
            status = "observed"
        elif expected:
            status = "missing"
        elif ev is not None:
            status = "unexpected"
        else:
            status = "not_expected"
        out.append(dict(stage=stage, timestamp=_s(ev["timestamp"]) if ev else None, status=status,
                        evidence=bool(ev is not None and captured), detail=detail,
                        domain=ev["domain"] if ev else None))

    add("Impression", first("IMPRESSION"))
    clk = first("CLICK")
    add("Click", clk, ok=row["click_correlated"],
        detail="" if row["click_correlated"] else "Click seen but not linked to its impression")
    hops = {e["hop_number"]: e for e in evs if e["event_type"] == "REDIRECT"}
    for n in range(1, row["expected_redirect_hops"] + 1):
        add(f"Redirect hop {n}", hops.get(n), detail="HTTP 302" if n in hops else "Hop not logged by telemetry")
    land = first("LANDING")
    add("Landing", land, expected=row["landing_expected"],
        detail="Blocked inline before landing" if row["inline_blocked"] else
        ("" if land or not row["landing_expected"] else "Landing event not logged"))
    cred = first("CREDENTIAL_ENTRY")
    if row["credential_event"]:
        add("Credential entry (test event)", cred, detail="Synthetic event only; no secret captured")
    dl = first("DOWNLOAD")
    if dl:
        add("Download (test artifact)", dl, detail="Harmless artifact; never executed")
    exp_det = row["expected_detection"]
    add("Detection", first("DETECTION"), expected=exp_det, detail=row["detection_rule"] or "")
    add("Alert", first("ALERT"), expected=exp_det)
    add("Triage", first("TRIAGE_START"), expected=exp_det,
        detail=(row["incident"] or {}).get("investigation_status", "") if row["incident"] else "")
    ce = first("CONTAINMENT_EFFECTIVE") or first("CONTAINMENT_FAILED")
    add("Containment", ce, expected=row["expected_containment"],
        ok=bool(first("CONTAINMENT_EFFECTIVE")),
        detail=("Failed: block did not propagate" if first("CONTAINMENT_FAILED") else
                ("Legitimate destination wrongly blocked" if row["legit_blocked"] else "")))
    return out


def compute_metrics(rows):
    n = len(rows)
    attack = [r for r in rows if r["expected_detection"]]
    benign = [r for r in rows if r["benign"]]

    clicks_corr = sum(1 for r in rows if r["click_correlated"])
    landings_obs = sum(1 for r in rows if r["landing_logged"])
    blocked_inline = sum(1 for r in rows if r["inline_blocked"])
    missing_landing = sum(1 for r in rows if "LANDING_NOT_LOGGED" in r["gaps"])

    exp_hops = sum(r["expected_redirect_hops"] for r in rows)
    log_hops = sum(r["logged_redirect_hops"] for r in rows)

    ev_exp = sum(1 for r in rows for k in EVIDENCE_ITEMS if r["evidence"][k]["expected"])
    ev_cap = sum(1 for r in rows for k in EVIDENCE_ITEMS if r["evidence"][k]["expected"] and r["evidence"][k]["captured"])

    cred = [r for r in rows if r["credential_event"]]
    detected_attack = sum(1 for r in attack if r["actual_detection"])
    contained_attack = sum(1 for r in attack if r["actual_containment"])
    attempted = [r for r in attack if r["containment"]]

    recon = sum(1 for r in rows if r["click_correlated"] and r["logged_redirect_hops"] == r["expected_redirect_hops"]
                and (r["landing_logged"] or not r["landing_expected"]))

    alerts = [r for r in rows if r["alert"]]
    return dict(
        impression_click_visibility=_pct(clicks_corr, n),
        click_landing_visibility=dict(**_pct(landings_obs, n), blocked_inline=blocked_inline,
                                      missing_telemetry=missing_landing),
        detection_coverage=_pct(detected_attack, len(attack)),
        ttd=_stats([r["ttd_s"] for r in rows if r["ttd_s"] is not None]),
        ttt=_stats([r["ttt_s"] for r in rows if r["ttt_s"] is not None]),
        ttc=_stats([r["ttc_s"] for r in rows if r["ttc_s"] is not None]),
        blocking_propagation=_stats([r["propagation_s"] for r in rows if r["propagation_s"] is not None]),
        redirect_inspection=_pct(log_hops, exp_hops),
        containment_success=dict(**_pct(contained_attack, len(attack)), attempted=len(attempted),
                                 failed=sum(1 for r in attempted if not r["actual_containment"])),
        false_positive=dict(legitimate_tested=len(benign),
                            legitimate_with_incident=sum(1 for r in benign if r["actual_detection"]),
                            legitimate_blocked=sum(1 for r in benign if r["legit_blocked"]),
                            rate=_pct(sum(1 for r in benign if r["actual_detection"]), len(benign))),
        identity_protection=_pct(sum(1 for r in cred if r["credential_detected"]), len(cred)),
        evidence_completeness=dict(**_pct(ev_cap, ev_exp), label="POC evidence-completeness metric (not an industry standard)"),
        journey_reconstruction=_pct(recon, n),
        alerts=dict(total=len(alerts),
                    true_positive=sum(1 for r in alerts if not r["benign"]),
                    false_positive=sum(1 for r in alerts if r["benign"]),
                    by_severity={s: sum(1 for r in alerts if r["alert"]["severity"] == s) for s in ("High", "Medium", "Low")}),
        totals=dict(tests=n, attack_tests=len(attack), benign_tests=len(benign), pass_=sum(1 for r in rows if r["result"] == "Pass"),
                    fail=sum(1 for r in rows if r["result"] == "Fail")),
    )


DEFINITIONS = [
    dict(id="impression_click_visibility", name="Impression to Click Visibility", category="Visibility",
         formula="correlated clicks / controlled impressions x 100",
         start="Impression logged", end="Click logged with its impression_id",
         note="The red team clicks every controlled impression, so this measures Blue-side correlation, not CTR."),
    dict(id="click_landing_visibility", name="Click to Landing Visibility", category="Visibility",
         formula="correlated landing events / controlled clicks x 100",
         start="Click", end="Landing event logged",
         note="Journeys blocked inline before landing lower this figure; the breakdown separates blocks from telemetry loss."),
    dict(id="detection_coverage", name="Detection Coverage", category="Detection",
         formula="attack paths with the expected detection / total attack paths x 100",
         start="-", end="-", note="Benign controls are excluded from the denominator."),
    dict(id="ttd", name="Time to Detection (TTD)", category="Response speed",
         formula="detection timestamp - first redirect hop (attack event)", start="First redirect hop",
         end="Detection", note="Detection latency is SIMULATED per rule."),
    dict(id="ttt", name="Time to Triage (TTT)", category="Response speed",
         formula="triage start - alert creation", start="Alert created", end="Triage started",
         note="SOC timings are SIMULATED."),
    dict(id="ttc", name="Time to Containment (TTC)", category="Response speed",
         formula="containment effective - alert creation", start="Alert created", end="Containment effective",
         note="Failed containments are excluded from the statistics and reported separately."),
    dict(id="blocking_propagation", name="Blocking Propagation Time", category="Containment",
         formula="containment effective - containment requested", start="Block requested",
         end="Block effective", note="SIMULATED."),
    dict(id="containment_success", name="Containment Success Rate", category="Containment",
         formula="attack paths successfully contained / total attack paths x 100", start="-", end="-",
         note="Undetected paths count as not contained."),
    dict(id="redirect_inspection", name="Redirect Inspection Coverage", category="Visibility",
         formula="redirect hops logged / total redirect hops x 100", start="-", end="-", note=""),
    dict(id="false_positive", name="False Positive / Legitimate Destination Check", category="Safety / quality",
         formula="benign controls generating an incident / benign controls x 100", start="-", end="-",
         note="Only two benign controls exist, so the rate is illustrative."),
    dict(id="identity_protection", name="Identity Protection", category="Detection",
         formula="credential-simulation events detected / executed x 100", start="-", end="-",
         note="Synthetic test events only. No credential or secret is ever collected."),
    dict(id="evidence_completeness", name="Evidence Completeness", category="Safety / quality",
         formula="evidence items captured / evidence items expected x 100", start="-", end="-",
         note="POC metric over a 10-item checklist; not an industry standard."),
    dict(id="journey_reconstruction", name="Journey Reconstruction", category="Safety / quality",
         formula="journeys with impression, linked click, all hops and landing (if expected) / total journeys x 100",
         start="-", end="-", note=""),
]


# ---------------- Findings ----------------
GAP_INFO = {
    "DETECTION_MISSED": ("Expected detection did not fire", "High",
                         "An attack path completed without an alert."),
    "FALSE_POSITIVE": ("Legitimate destination flagged and blocked", "High",
                       "A legitimate destination was blocked, causing business disruption."),
    "CONTAINMENT_FAILED": ("Containment action failed", "High",
                           "The suspicious destination stayed reachable after the block request."),
    "REDIRECT_HOP_MISSING": ("Redirect hop missing from telemetry", "Medium",
                             "The SOC cannot reconstruct the complete redirect chain."),
    "LANDING_NOT_LOGGED": ("Landing event missing from telemetry", "Medium",
                           "The journey cannot be followed to its final destination."),
    "CLICK_NOT_CORRELATED": ("Click not correlated to its impression", "Medium",
                             "Impression-to-click visibility is reduced; attribution of the journey is weaker."),
}
REMEDIATION = {
    ("DETECTION_MISSED", "MAL-006"): "Enable the credential-on-unapproved-origin rule (R5).",
    ("DETECTION_MISSED", "MAL-009"): "Evaluate the final destination of the redirect chain, not only the first host.",
    ("FALSE_POSITIVE", "MAL-012"): "Allow-list the approved partner domain and tune the lookalike rule (R3).",
    ("CONTAINMENT_FAILED", "MAL-010"): "Investigate block propagation to the enforcement point; add a failure alert and retry.",
    ("REDIRECT_HOP_MISSING", "MAL-005"): "Improve redirect logging so every hop is captured.",
    ("LANDING_NOT_LOGGED", "MAL-008"): "Restore landing-event logging for rotating domains.",
    ("CLICK_NOT_CORRELATED", "MAL-011"): "Preserve the impression identifier through the tracker used by this journey.",
}

SEVERITY_METHOD = ("POC convention, not an industry standard. High: an expected detection or containment did not "
                   "occur, or a legitimate destination was blocked. Medium: a visibility or evidence gap while "
                   "detection still worked. Low: reserved, unused in this POC.")


def build_findings(base_rows, retest_rows):
    """One finding per (scenario, gap type). A control gap hits every variant of a scenario, so grouping keeps
    the register readable. Status reflects how many affected journeys are fixed in the retest."""
    after = {r["test_id"]: r for r in retest_rows}
    groups = {}
    for r in base_rows:
        for g in r["gaps"]:
            groups.setdefault((r["scenario_code"], g), []).append(r)
    findings = []
    for n, ((code, g), rows) in enumerate(sorted(groups.items()), start=1):
        title, sev, impact = GAP_INFO[g]
        still = [r["test_id"] for r in rows if g in after[r["test_id"]]["gaps"]]
        fixed = len(rows) - len(still)
        status = "Open" if fixed == 0 else ("Remediated (POC scenario)" if not still else "Partially remediated")
        retest_status = ("Still failing in retest" if fixed == 0 else
                         ("Verified in POC retest" if not still else f"{len(still)} of {len(rows)} still failing"))
        name = rows[0]["scenario_name"]
        findings.append(dict(
            finding_id=f"FIND-{n:03d}", scenario_code=code, scenario_name=name, gap_type=g,
            finding_title=f"{title} ({name})",
            description=f"{code} {name}: {title.lower()}. Affects {len(rows)} of its journeys in the baseline run.",
            impact=impact, severity=sev, affected_tests=[r["test_id"] for r in rows], affected_count=len(rows),
            still_failing_tests=still, test_id=rows[0]["test_id"],
            evidence=f"{len(rows)} journeys, first {rows[0]['test_id']} (baseline run)",
            remediation=REMEDIATION.get((g, code), "To be confirmed"),
            status=status, retest_status=retest_status, data_origin="synthetic"))
    return findings


def build_retest(base_rows, retest_rows, findings):
    """Per scenario before/after summary."""
    after = {r["test_id"]: r for r in retest_rows}
    fixes = {}
    for f in findings:
        if f["status"] != "Open":
            fixes.setdefault(f["scenario_code"], []).append(f["remediation"])
    out, order = [], []
    for r in base_rows:
        if r["scenario_code"] not in order:
            order.append(r["scenario_code"])
    for code in order:
        b = [r for r in base_rows if r["scenario_code"] == code]
        a = [after[r["test_id"]] for r in b]
        def snap(rows):
            return dict(journeys=len(rows), passed=sum(1 for r in rows if r["result"] == "Pass"),
                        failed=sum(1 for r in rows if r["result"] == "Fail"),
                        detected=sum(1 for r in rows if r["actual_detection"]),
                        contained=sum(1 for r in rows if r["actual_containment"]),
                        gaps=sorted({g for r in rows for g in r["gaps"]}))
        sb, sa = snap(b), snap(a)
        out.append(dict(scenario_code=code, scenario_name=b[0]["scenario_name"], baseline=sb, retest=sa,
                        changed=sb["passed"] != sa["passed"], fixes_applied=fixes.get(code, []),
                        first_test_id=b[0]["test_id"]))
    return out

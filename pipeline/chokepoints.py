"""Choke-point analysis.

A choke point is one place many attack journeys pass through, so one action stops them all.

1. Infrastructure choke points: shared advertiser account, registrar, hosting provider or redirect
   host family. Ranked by how many attack journeys use them. Legitimate journeys on the same node
   are reported as collateral damage. A greedy cumulative curve shows how many attack paths the top
   N actions would cut off, and `edges` link scenarios to nodes for the graph view.
2. Detection choke points: for each rule, which attack tests it detects and which tests it is the
   ONLY detector for (a single point of failure).

Infrastructure attributes are synthetic labels (see scenarios.INFRA). A node needs at least
MIN_PATHS attack journeys to count as a choke point.
"""
from collections import Counter

from config import PROFILES, RULES
from scenarios import TRUSTED_CATEGORIES

MIN_PATHS = 3
TYPE_LABEL = {
    "ad_account": "Advertiser account",
    "registrar": "Registrar",
    "hosting": "Hosting provider",
    "redirect_family": "Redirect host family",
}
ACTION = {
    "ad_account": "Suspend the advertiser account",
    "registrar": "Request takedown of the domains at this registrar",
    "hosting": "Block the hosting range at the proxy and DNS layer",
    "redirect_family": "Block the whole redirect domain family",
}
TYPE_ORDER = list(TYPE_LABEL)


def _family(domain):
    return ".".join(domain.split(".")[-2:])


def _nodes(tests, registry):
    nodes = {}
    for t in tests:
        keys = {(k, v) for k, v in t["infra"].items()}
        for h in t["hops"][:-1]:
            if registry.get(h, {}).get("category") not in TRUSTED_CATEGORIES:
                keys.add(("redirect_family", _family(h)))
        for typ, name in keys:
            n = nodes.setdefault(f"{typ}:{name}", dict(
                id=f"{typ}:{name}", type=typ, type_label=TYPE_LABEL[typ], name=name,
                action=ACTION[typ], attack=[], benign=[]))
            (n["benign"] if t["benign"] else n["attack"]).append(t["test_id"])
    out = [n for n in nodes.values() if len(n["attack"]) >= MIN_PATHS]
    out.sort(key=lambda n: (TYPE_ORDER.index(n["type"]), n["name"]))
    return out


def build(tests, results, registry):
    attack_ids = [t["test_id"] for t in tests if not t["benign"]]
    code_of = {t["test_id"]: t["scenario_code"] for t in tests}
    nodes = _nodes(tests, registry)

    for n in nodes:
        n["attack_count"] = len(n["attack"])
        n["attack_share"] = round(100.0 * len(n["attack"]) / len(attack_ids), 1)
        n["by_scenario"] = dict(sorted(Counter(code_of[x] for x in n["attack"]).items()))
        n["per_run"] = {}
        for run, res in results.items():
            by_id = {r["test_id"]: r for r in res["rows"]}
            unc = [tid for tid in n["attack"] if not by_id[tid]["actual_containment"]]
            n["per_run"][run] = dict(contained=len(n["attack"]) - len(unc), uncontained=len(unc), uncontained_tests=unc)

    # Greedy cumulative coverage over SAFE nodes only (nodes that carry no legitimate journeys), because
    # blocking a node with legitimate traffic causes collateral damage. Most newly covered paths first.
    for n in nodes:
        n["safe"] = len(n["benign"]) == 0
    safe_nodes = [n for n in nodes if n["safe"]]
    remaining, covered, chosen, curve = set(attack_ids), set(), set(), []
    while remaining:
        best, best_key, best_new = None, None, None
        for n in safe_nodes:
            if n["id"] in chosen:
                continue
            new = set(n["attack"]) & remaining
            if not new:
                continue
            key = (len(new), -len(n["benign"]))
            if best_key is None or key > best_key:
                best, best_key, best_new = n, key, new
        if best is None:
            break
        chosen.add(best["id"])
        remaining -= best_new
        covered |= best_new
        curve.append(dict(step=len(curve) + 1, node_id=best["id"], label=f"{best['type_label']} {best['name']}",
                          newly_covered=sorted(best_new), covered=len(covered),
                          cumulative_pct=round(100.0 * len(covered) / len(attack_ids), 1),
                          collateral=len(best["benign"])))
    for n in nodes:
        n["curve_step"] = next((c["step"] for c in curve if c["node_id"] == n["id"]), None)
    nodes.sort(key=lambda n: (-n["attack_count"], len(n["benign"]), TYPE_ORDER.index(n["type"]), n["name"]))

    edges = [dict(scenario_code=sc, node_id=n["id"], count=cnt) for n in nodes for sc, cnt in n["by_scenario"].items()]

    # Detection choke points
    def rule_rows(rows, enabled):
        out = []
        for rid, r in RULES.items():
            fired = sorted(x["test_id"] for x in rows if x["expected_detection"] and rid in x["rules_fired"])
            sole = sorted(x["test_id"] for x in rows if x["expected_detection"] and set(x["rules_fired"]) == {rid})
            fp = sorted(x["test_id"] for x in rows if x["benign"] and rid in x["rules_fired"])
            out.append(dict(rule=rid, name=r["name"], severity=r["severity"], enabled=rid in enabled,
                            fires_on=fired, sole_detector_for=sole, false_positives=fp))
        return out

    detection = {run: rule_rows(res["rows"], PROFILES[run]["enabled_rules"]) for run, res in results.items()}
    needed_by = {r["rule"]: r["sole_detector_for"] for r in detection["retest"]}  # all rules enabled
    for run in detection:
        for r in detection[run]:
            r["needed_by"] = needed_by[r["rule"]]

    attack_codes = sorted({code_of[x] for x in attack_ids})
    return dict(
        attack_total=len(attack_ids), attack_scenarios=attack_codes, nodes=nodes, edges=edges, curve=curve,
        uncovered=sorted(remaining), detection=detection, min_paths=MIN_PATHS,
        curve_note="The curve only uses nodes that carry no legitimate journeys. Nodes that do are listed in the table "
                   "but are unsafe to block wholesale.",
        test_scenarios={t["test_id"]: t["scenario_code"] for t in tests},
        notes=["Advertiser account, registrar and hosting labels are synthetic attributes added for this analysis. "
               "They do not change any event, rule or metric.",
               f"A node needs at least {MIN_PATHS} attack journeys to count as a choke point.",
               "Collateral lists legitimate test journeys that share the node, so blocking it would hit them too."])

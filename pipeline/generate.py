"""Red-team event generator.

Expands each scenario into VARIANTS journeys (different domains, ages, timings, infrastructure) and
produces the GROUND TRUTH of what each journey did. The Blue side never reads this directly;
detect.observe() applies a telemetry profile (dropped events, unlinked clicks) first.
"""
import random
from datetime import timedelta

from config import (SEED, START, JOURNEY_SPACING_S, VARIANTS, AD_SURFACE_DOMAIN, PLATFORM_LABEL, USER_AGENTS,
                    BRAND_TOKEN)
from scenarios import SCENARIOS, INFRA, INFRA_POOLS


def _ev(test_id, scenario_code, ts, etype, **kw):
    e = dict(test_id=test_id, scenario_code=scenario_code, timestamp=ts, event_type=etype, source="red_team",
             domain=None, url=None, hop_number=None, http_status=None, severity=None, rule=None,
             status="observed", data_origin="synthetic", metadata={})
    e.update(kw)
    return e


def _infra(code, benign, rng, variant):
    """Base infrastructure labels most of the time, a random alternative otherwise."""
    base = INFRA[code]
    out = {}
    for key, pool in INFRA_POOLS.items():
        roll = rng.random()  # always draw, so the sequence does not depend on the branch taken
        if variant == 1 or roll < 0.7 or (benign and key == "ad_account"):
            out[key] = base[key]
        else:
            out[key] = rng.choice([p for p in pool if p != base[key]])
    return out


def build_truth():
    """Return (tests, events, registry, known_bad)."""
    registry, known_bad, tests, events = {}, set(), [], []
    g = 0
    for i, s in enumerate(SCENARIOS):
        for v in range(1, VARIANTS + 1):
            rng = random.Random(SEED * 100 + g)
            n = g + 1
            tid = f"TEST-{n:03d}"
            code = s["code"]

            # --- expand the hop specs for this variant ---
            specs = list(s["hops"])
            if s.get("extra_hop") and v % 2 == 0:
                specs.insert(len(specs) - 1, s["extra_hop"])
            hop_domains = []
            for spec in specs:
                dom = spec["d"] if (v == 1 or spec["shared"]) else f"v{v}.{spec['d']}"
                age = spec["age"]
                if isinstance(age, tuple):
                    age = age[0] if v == 1 else rng.randint(*age)
                registry[dom] = dict(age_days=age, category=spec["cat"])
                if spec["bad"]:
                    known_bad.add(dom)
                hop_domains.append(dom)
            disp = s["display_domain"]
            if disp != "contoso.test" and v > 1:
                disp = f"v{v}.{disp}"
            expected_hops = len(hop_domains)

            ids = dict(
                campaign_id=f"CAMP-{i + 1:03d}", ad_id=f"AD-{n:03d}", creative_id=f"CRE-{i + 1:02d}-{v}",
                impression_id=f"IMP-{1000 + n}", click_id=f"CLICK-{1000 + n}",
                user_id=f"USER-{n:03d}", device_id=f"DEV-{n:03d}", source_ip=f"10.20.0.{10 + n}",
                user_agent=USER_AGENTS[g % len(USER_AGENTS)],
            )
            infra = _infra(code, s["benign"], random.Random(SEED * 7 + g), v)
            t0 = START + timedelta(seconds=g * JOURNEY_SPACING_S + rng.randint(0, 40))
            test = dict(test_id=tid, scenario_code=code, scenario_name=s["name"], variant=v,
                        platform=PLATFORM_LABEL, expected_detection=not s["benign"],
                        expected_containment=not s["benign"], expected_hops=expected_hops,
                        benign=s["benign"], t0=t0, scenario=s, hops=hop_domains, display_domain=disp,
                        infra=infra, **ids)
            tests.append(test)

            ev = [_ev(tid, code, t0, "IMPRESSION", domain=disp, url=f"https://{disp}/",
                      metadata=dict(ids, keyword_class=s["keyword_class"], campaign_type=s["campaign_type"],
                                    ad_title=s["ad_title"], placement=f"{s['campaign_type']}-simulated"))]
            t = t0 + timedelta(seconds=rng.randint(8, 30))
            ev.append(_ev(tid, code, t, "CLICK", domain=AD_SURFACE_DOMAIN, url=f"https://{hop_domains[0]}/",
                          metadata=dict(ids, impression_id=ids["impression_id"])))
            prev = AD_SURFACE_DOMAIN
            for h, dest in enumerate(hop_domains, start=1):
                t = t + timedelta(seconds=1)
                ev.append(_ev(tid, code, t, "REDIRECT", domain=dest, url=f"https://{dest}/", hop_number=h,
                              http_status=302,
                              metadata=dict(click_id=ids["click_id"], source_domain=prev,
                                            ip_address=f"198.51.100.{10 + (g * 3 + h) % 240}",
                                            user_agent=ids["user_agent"], cloaking=s["cloaking"])))
                prev = dest
            final = hop_domains[-1]
            t = t + timedelta(seconds=rng.randint(2, 4))
            ev.append(_ev(tid, code, t, "LANDING", domain=final, url=f"https://{final}/", http_status=200,
                          metadata=dict(click_id=ids["click_id"], landing_id=f"LAND-{1000 + n}",
                                        device_id=ids["device_id"], source_ip=ids["source_ip"],
                                        user_agent=ids["user_agent"],
                                        note="Cloaked: scanners would see a decoy page" if s["cloaking"] else "")))
            if s["credential"]:
                ev.append(_ev(tid, code, t + timedelta(seconds=25), "CREDENTIAL_ENTRY", domain=final,
                              url=f"https://{final}/login",
                              metadata=dict(synthetic_user=ids["user_id"],
                                            note="Test event only. No password, token or secret is captured.")))
            if s["download"]:
                ev.append(_ev(tid, code, t + timedelta(seconds=6), "DOWNLOAD", domain=final,
                              url=f"https://{final}/setup_installer.test.bin",
                              metadata=dict(artifact="harmless_test_artifact", executed=False)))
            events.extend(ev)
            g += 1
    return tests, events, registry, known_bad

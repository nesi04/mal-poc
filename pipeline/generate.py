"""Red-team event generator.

Produces the GROUND TRUTH of what each controlled journey did. The Blue side never reads this
directly; detect.observe() applies a telemetry profile (dropped events, unlinked clicks) first.
"""
import random
from datetime import timedelta

from config import (SEED, START, JOURNEY_SPACING_S, AD_SURFACE_DOMAIN, PLATFORM_LABEL, USER_AGENTS)
from scenarios import SCENARIOS


def _ev(test_id, ts, etype, **kw):
    e = dict(test_id=test_id, timestamp=ts, event_type=etype, source="red_team", domain=None, url=None,
             hop_number=None, http_status=None, severity=None, rule=None, status="observed",
             data_origin="synthetic", metadata={})
    e.update(kw)
    return e


def build_truth():
    """Return (tests, events). tests = scenario + identifiers; events = ground-truth red events."""
    tests, events = [], []
    for i, s in enumerate(SCENARIOS):
        rng = random.Random(SEED * 100 + i)
        tid = f"TEST-{i + 1:03d}"
        n = i + 1
        ids = dict(
            campaign_id=f"CAMP-{1 if s['campaign_type'] == 'search' else 2:03d}",
            ad_id=f"AD-{n:03d}", creative_id=f"CRE-{n:03d}",
            impression_id=f"IMP-{1000 + n}", click_id=f"CLICK-{1000 + n}",
            user_id=f"USER-{n:03d}", device_id=f"DEV-{n:03d}", source_ip=f"10.20.0.{10 + n}",
            user_agent=USER_AGENTS[i % len(USER_AGENTS)],
        )
        t0 = START + timedelta(seconds=i * JOURNEY_SPACING_S + rng.randint(0, 40))
        expected_hops = len(s["hops"])
        test = dict(test_id=tid, scenario_code=s["code"], scenario_name=s["name"],
                    platform=PLATFORM_LABEL, expected_detection=not s["benign"],
                    expected_containment=not s["benign"], expected_hops=expected_hops,
                    benign=s["benign"], t0=t0, scenario=s, **ids)
        tests.append(test)

        first_url = f"https://{s['hops'][0]}/"
        ev = []
        ev.append(_ev(tid, t0, "IMPRESSION", domain=s["display_domain"], url=f"https://{s['display_domain']}/",
                      metadata=dict(ids, keyword_class=s["keyword_class"], campaign_type=s["campaign_type"],
                                    ad_title=s["ad_title"], placement=f"{s['campaign_type']}-simulated")))
        t = t0 + timedelta(seconds=rng.randint(8, 30))
        ev.append(_ev(tid, t, "CLICK", domain=AD_SURFACE_DOMAIN, url=first_url,
                      metadata=dict(ids, impression_id=ids["impression_id"])))
        prev = AD_SURFACE_DOMAIN
        for h, dest in enumerate(s["hops"], start=1):
            t = t + timedelta(seconds=1)
            ev.append(_ev(tid, t, "REDIRECT", domain=dest, url=f"https://{dest}/", hop_number=h, http_status=302,
                          metadata=dict(click_id=ids["click_id"], source_domain=prev,
                                        ip_address=f"198.51.100.{20 + i * 3 + h}",
                                        user_agent=ids["user_agent"], cloaking=s["cloaking"])))
            prev = dest
        final = s["hops"][-1]
        t = t + timedelta(seconds=rng.randint(2, 4))
        ev.append(_ev(tid, t, "LANDING", domain=final, url=f"https://{final}/", http_status=200,
                      metadata=dict(click_id=ids["click_id"], landing_id=f"LAND-{1000 + n}",
                                    device_id=ids["device_id"], source_ip=ids["source_ip"],
                                    user_agent=ids["user_agent"],
                                    note="Cloaked: scanners would see a decoy page" if s["cloaking"] else "")))
        if s["credential"]:
            ev.append(_ev(tid, t + timedelta(seconds=25), "CREDENTIAL_ENTRY", domain=final,
                          url=f"https://{final}/login",
                          metadata=dict(synthetic_user=ids["user_id"],
                                        note="Test event only. No password, token or secret is captured.")))
        if s["download"]:
            ev.append(_ev(tid, t + timedelta(seconds=6), "DOWNLOAD", domain=final,
                          url=f"https://{final}/setup_installer.test.bin",
                          metadata=dict(artifact="harmless_test_artifact", executed=False)))
        events.extend(ev)
    return tests, events

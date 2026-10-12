"""Central configuration for the Malvertising Security POC pipeline.

Everything here is SIMULATED. No real ads, domains, credentials or malware are involved.
All domains use the reserved .test TLD. IPs use RFC 5737 documentation ranges.
"""
from datetime import datetime, timezone

SEED = 42
START = datetime(2026, 10, 9, 9, 0, 0, tzinfo=timezone.utc)
JOURNEY_SPACING_S = 420  # one journey every 7 minutes
VARIANTS = 8             # journeys generated per scenario

# Synthetic brand (never a real brand)
BRAND_TOKEN = "contoso"
APPROVED_BRAND_DOMAINS = {"contoso.test", "login.contoso.test"}
APPROVED_AUTH_ORIGINS = {"login.contoso.test"}

FIRST_SEEN_DAYS = 7      # R2: domain younger than this = first-seen
YOUNG_HOP_DAYS = 30      # R4: intermediate hop younger than this = suspicious

AD_SURFACE_DOMAIN = "ads.poc-adsurface.test"
PLATFORM_LABEL = "Simulated-Search-Ads"

# Detection rules. latency = simulated seconds from trigger event to detection.
RULES = {
    "R1": dict(name="KNOWN_BAD_DESTINATION", severity="High", latency=(1, 1), inline=True,
               auto_contain=False, action="domain_block",
               desc="Destination domain appears in the threat-intel table"),
    "R2": dict(name="FIRST_SEEN_DOMAIN", severity="Medium", latency=(30, 90), inline=False,
               auto_contain=False, action="domain_block",
               desc="Destination domain is younger than 7 days"),
    "R3": dict(name="LOOKALIKE_DOMAIN", severity="Medium", latency=(25, 80), inline=False,
               auto_contain=True, action="domain_block",
               desc="Hostname contains the protected brand token but is not an approved domain"),
    "R4": dict(name="SUSPICIOUS_REDIRECT_CHAIN", severity="Medium", latency=(40, 110), inline=False,
               auto_contain=False, action="domain_block",
               desc="Two or more redirect hops through a young intermediate host"),
    "R5": dict(name="CREDENTIAL_ON_UNAPPROVED_ORIGIN", severity="High", latency=(20, 60), inline=False,
               auto_contain=False, action="domain_block",
               desc="Synthetic credential-entry event on a non-approved authentication origin"),
    "R6": dict(name="DOWNLOAD_AFTER_AD_CLICK", severity="High", latency=(15, 50), inline=False,
               auto_contain=False, action="URL_block",
               desc="File download shortly after an ad click"),
}

ALL_RULES = set(RULES)

# Two runs of the same journeys: baseline controls, then controls after simulated remediation.
PROFILES = {
    "baseline": dict(
        label="Baseline",
        description="Initial control configuration, with the telemetry and rule gaps being tested.",
        enabled_rules={"R1", "R2", "R3", "R4", "R6"},   # R5 not enabled yet
        evaluate_final_destination=False,                # only the first hop destination is evaluated
        allowlist_tokens=set(),
        # Control gaps are keyed by scenario, so they affect every variant of that scenario.
        dropped_events={("MAL-005", "REDIRECT", 2), ("MAL-008", "LANDING", 0)},
        unlinked_click_scenarios={"MAL-011"},
        failed_containment_scenarios={"MAL-010"},
    ),
    "retest": dict(
        label="Retest (after simulated fixes)",
        description="Same journeys after: R5 enabled, final-destination evaluation, hop and landing "
                    "logging repaired, partner domains allow-listed. Two issues are deliberately left open.",
        enabled_rules=set(ALL_RULES),
        evaluate_final_destination=True,
        allowlist_tokens={"contoso-events"},
        dropped_events=set(),
        unlinked_click_scenarios={"MAL-011"},            # still open
        failed_containment_scenarios={"MAL-010"},        # still open
    ),
}

ANALYSTS = ["ANALYST-01", "ANALYST-02", "ANALYST-03"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) POC-Browser/1.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) POC-Browser/1.0",
    "Mozilla/5.0 (X11; Linux x86_64) POC-Browser/1.0",
]

"""Red-team scenario catalog. All domains are reserved .test names (synthetic).

Each scenario is modelled on a pattern from the case-study dossier. `hops` is a list of hop specs;
the last one is the final landing domain. generate.py expands each scenario into several variants
(different domains, domain ages, timings and, for some scenarios, an extra redirect hop).

Hop spec fields: d = domain, age = (min, max) days or an int, cat = registry category,
shared = same domain in every variant, bad = listed in the synthetic threat-intel table.
"""


def H(d, age, cat="uncategorised", shared=False, bad=False):
    return dict(d=d, age=age, cat=cat, shared=shared, bad=bad)


SCENARIOS = [
    dict(code="MAL-001", name="Known-bad destination", campaign_type="search", keyword_class="software-download",
         ad_title="Free PDF Tool - Official Download", display_domain="pdf-tools-hub.test",
         hops=[H("secure-docs-verify.test", (30, 400), "phishing", bad=True)], benign=False, credential=False,
         download=False, cloaking=False,
         pattern="Known-bad final destination (dossier cases 3, 5, 6, 8)",
         intended_signal="R1 threat-intel match, blocked inline before landing"),
    dict(code="MAL-002", name="First-seen domain", campaign_type="search", keyword_class="software-download",
         ad_title="Fast File Converter", display_domain="file-convert-pro.test",
         hops=[H("fresh-offers-hub.test", (0, 6))], benign=False, credential=False, download=False, cloaking=False,
         pattern="Newly registered / rotating domain (dossier cases 3, 7)",
         intended_signal="R2 first-seen domain"),
    dict(code="MAL-003", name="Lookalike domain", campaign_type="display", keyword_class="cloud-login",
         ad_title="Contoso Account Security Notice", display_domain="contoso.test",
         hops=[H("contoso-login-secure.test", (10, 60))], benign=False, credential=False, download=False,
         cloaking=False, pattern="Brand lookalike hostname (dossier cases 4, 5)",
         intended_signal="R3 lookalike domain"),
    dict(code="MAL-004", name="Multi-hop redirect via disposable host", campaign_type="search",
         keyword_class="collab-app", ad_title="Team Meeting App - Download", display_domain="meet-app-center.test",
         hops=[H("r1.hop-relay.test", (0, 3), "redirector"), H("account-check-portal.test", (10, 40))],
         extra_hop=H("rb.hop-relay.test", (0, 3), "redirector"), benign=False, credential=False, download=False,
         cloaking=False, pattern="Multi-hop redirect through disposable host (dossier cases 4, 7, 8)",
         intended_signal="R4 redirect chain (plus R2 on the relay). Every other variant adds a third hop"),
    dict(code="MAL-005", name="Two-hop redirect, second hop unlogged", campaign_type="display",
         keyword_class="invoice-docs", ad_title="Invoice Review Center", display_domain="invoice-review.test",
         hops=[H("r2.hop-relay.test", (0, 3), "redirector"), H("billing-review-center.test", (10, 40))],
         benign=False, credential=False, download=False, cloaking=False, pattern="Redirect telemetry gap",
         intended_signal="Detected, but hop 2 missing from telemetry in baseline"),
    dict(code="MAL-006", name="Ad-to-credential simulation", campaign_type="search", keyword_class="cloud-login",
         ad_title="Single Sign-On Portal", display_domain="sso-portal.test",
         hops=[H("sso-verify-portal.test", (30, 120))], benign=False, credential=True, download=False,
         cloaking=False,
         pattern="Credential-harvest page (dossier cases 1, 4). Synthetic test event only; no secret captured",
         intended_signal="R5 credential on unapproved origin (rule disabled in baseline)"),
    dict(code="MAL-007", name="Benign control", campaign_type="search", keyword_class="cloud-login",
         ad_title="Contoso Official Site", display_domain="contoso.test",
         hops=[H("contoso.test", 3000, "business", shared=True)], benign=True, credential=False, download=False,
         cloaking=False, pattern="Clean legitimate ad (control)", intended_signal="No incident"),
    dict(code="MAL-008", name="Rapidly changing URL", campaign_type="display", keyword_class="shopping-offer",
         ad_title="Limited Time Offer", display_domain="deal-finder.test",
         hops=[H("a8f3k.rotating-edge.test", 0, "redirector"), H("promo-gate-7q.test", 0)],
         extra_hop=H("b2.rotating-edge.test", 0, "redirector"), benign=False, credential=False, download=False,
         cloaking=False, pattern="Rotating infrastructure (dossier cases 3, 7)",
         intended_signal="Behavioural detection (R2 + R4), not IOC; landing event lost in baseline"),
    dict(code="MAL-009", name="Trusted-site redirect", campaign_type="search", keyword_class="invoice-docs",
         ad_title="Shared Document Viewer", display_domain="doc-viewer.test",
         hops=[H("files.trusted-cloud.test", 2500, "cloud-storage", shared=True),
               H("docs-share-review.test", (5, 30), "phishing", bad=True)],
         benign=False, credential=False, download=False, cloaking=False,
         pattern="Trusted domain as staging host (dossier cases 7, 8)",
         intended_signal="Final destination must be evaluated, not just the first host"),
    dict(code="MAL-010", name="Download after click", campaign_type="search", keyword_class="software-download",
         ad_title="System Update Center", display_domain="update-center.test",
         hops=[H("app-update-center.test", (8, 60))], benign=False, credential=False, download=True,
         cloaking=False,
         pattern="Post-click download (dossier cases 5, 6, 8). Harmless test artifact only",
         intended_signal="R6 download after ad click; containment fails in baseline"),
    dict(code="MAL-011", name="Cloaking", campaign_type="display", keyword_class="shopping-offer",
         ad_title="Exclusive Partner Offer", display_domain="partner-offers.test",
         hops=[H("traffic-filter.test", (0, 6), "redirector"), H("partner-offer-view.test", (10, 60))],
         benign=False, credential=False, download=False, cloaking=True,
         pattern="Visitor filtering / decoy page for scanners (dossier cases 2, 4, 7, 8)",
         intended_signal="R4 + R2; click not correlated to impression in baseline"),
    dict(code="MAL-012", name="Benign control, partner domain", campaign_type="search", keyword_class="collab-app",
         ad_title="Contoso Events Registration", display_domain="contoso-events.test",
         hops=[H("contoso-events.test", 800, "business")], benign=True, credential=False, download=False,
         cloaking=False, pattern="Clean legitimate ad containing the brand token (control)",
         intended_signal="Must not be blocked; lookalike rule false-positives in baseline"),
]

TRUSTED_CATEGORIES = {"business", "cloud-storage"}

# Base synthetic infrastructure labels per scenario, used by the choke-point analysis. generate.py
# gives each variant these values most of the time and a random alternative otherwise. They are
# invented names (no real provider, registrar or account) and change no event, rule or metric.
INFRA = {
    "MAL-001": dict(ad_account="ACCT-A", registrar="Registrar-Alpha", hosting="Host-Net-1"),
    "MAL-002": dict(ad_account="ACCT-A", registrar="Registrar-Beta", hosting="Host-Net-1"),
    "MAL-003": dict(ad_account="ACCT-B", registrar="Registrar-Alpha", hosting="Host-Net-2"),
    "MAL-004": dict(ad_account="ACCT-B", registrar="Registrar-Gamma", hosting="Host-Net-2"),
    "MAL-005": dict(ad_account="ACCT-C", registrar="Registrar-Gamma", hosting="Host-Net-2"),
    "MAL-006": dict(ad_account="ACCT-C", registrar="Registrar-Beta", hosting="Host-Net-3"),
    "MAL-007": dict(ad_account="ACCT-L", registrar="Registrar-Alpha", hosting="Host-Net-4"),
    "MAL-008": dict(ad_account="ACCT-D", registrar="Registrar-Gamma", hosting="Host-Net-3"),
    "MAL-009": dict(ad_account="ACCT-D", registrar="Registrar-Alpha", hosting="Host-Net-3"),
    "MAL-010": dict(ad_account="ACCT-A", registrar="Registrar-Beta", hosting="Host-Net-1"),
    "MAL-011": dict(ad_account="ACCT-D", registrar="Registrar-Gamma", hosting="Host-Net-3"),
    "MAL-012": dict(ad_account="ACCT-L", registrar="Registrar-Beta", hosting="Host-Net-2"),
}
INFRA_POOLS = dict(
    ad_account=["ACCT-A", "ACCT-B", "ACCT-C", "ACCT-D", "ACCT-E", "ACCT-F"],
    registrar=["Registrar-Alpha", "Registrar-Beta", "Registrar-Gamma", "Registrar-Delta"],
    hosting=["Host-Net-1", "Host-Net-2", "Host-Net-3", "Host-Net-4", "Host-Net-5"],
)

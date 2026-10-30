"""benignfilter.SCANNER_ASNS contracts (the known-scanner ASN list).

Pin the 2026-10-28 corrections: hosting / bulletproof ASNs are not scanner
orgs, and each scanner org keeps the ASNs its GeoLite2-ASN name shows.
"""
from __future__ import annotations

import benignfilter


def test_hosting_asns_are_not_scanner_orgs():
    assert 202425 not in benignfilter.SCANNER_ASNS   # IP Volume inc (bulletproof)
    assert 19994 not in benignfilter.SCANNER_ASNS    # Rackspace Hosting


def test_scanner_org_asns():
    s = benignfilter.SCANNER_ASNS
    assert s[398705] == s[398324] == s[398722] == "censys"
    assert {s[a] for a in (208843, 215778, 42969)} == {"alpha_strike"}
    assert s[211298] == "driftnet"

"""KG-lite finding-fusion (conclusions/graph) contracts.

Pin the graph semantics that the storyline report depends on:
  - strong entities (core_hash/chain/shared IP) fuse findings
  - a single shared hub ASN does NOT over-fuse (the blob guard)
  - findings with no qualifying link stay singletons
  - the parquet contract holds for the empty-findings case
All pure-unit (tiny dicts) so no corpus is needed.
"""
from __future__ import annotations

import json

import pyarrow as pa

from conclusions import graph


def _f(fid, pattern="p", sev="medium", ips=None, asns=None,
       km=None, src_ip_count=None, first="", last=""):
    ips = ips or []
    return {
        "finding_id": fid,
        "pattern_id": pattern,
        "pattern_title": pattern,
        "severity": sev,
        "category": "cat",
        "src_ip_count": src_ip_count if src_ip_count is not None else len(ips),
        "src_ips_sample": ",".join(ips),
        "asns_sample": "; ".join(asns or []),
        "countries_sample": "",
        "key_metrics": json.dumps(km or {}),
        "first_seen": first,
        "last_seen": last,
    }


def test_extract_entities_pulls_all_types():
    f = _f("a", ips=["1.1.1.1", "2.2.2.2"], asns=["AS10", "AS20"],
           km={"core_hash": "abc", "chain": "S6,S6,A"})
    e = graph.extract_entities(f)
    assert e["ip"] == {"1.1.1.1", "2.2.2.2"}
    assert e["asn"] == {"AS10", "AS20"}
    assert e["core_hash"] == {"abc"}
    assert e["chain"] == {"S6,S6,A"}


def test_shared_core_hash_fuses_findings():
    findings = [
        _f("a", ips=["1.1.1.1"], km={"core_hash": "deadbeef"}),
        _f("b", ips=["9.9.9.9"], km={"core_hash": "deadbeef"}),
    ]
    stories, links = graph.build_storylines(findings)
    assert len(links) == 1
    assert len(stories) == 1
    assert stories[0]["finding_count"] == 2
    assert json.loads(stories[0]["linking_entities"]) == {"core_hash": 1}


def test_shared_ip_fuses_findings():
    findings = [
        _f("a", ips=["5.5.5.5", "6.6.6.6"]),
        _f("b", ips=["6.6.6.6", "7.7.7.7"]),
    ]
    stories, _ = graph.build_storylines(findings)
    assert len(stories) == 1 and stories[0]["finding_count"] == 2


def test_single_shared_asn_does_not_fuse():
    # one shared ASN (weight 1.5) is below MIN_EDGE_WEIGHT -> no blob
    findings = [
        _f("a", ips=["1.1.1.1"], asns=["AS13335"]),
        _f("b", ips=["2.2.2.2"], asns=["AS13335"]),
    ]
    stories, links = graph.build_storylines(findings)
    assert links == []
    assert len(stories) == 2
    assert all(s["finding_count"] == 1 for s in stories)


def test_two_shared_asns_do_fuse():
    findings = [
        _f("a", asns=["AS1", "AS2"]),
        _f("b", asns=["AS1", "AS2"]),
    ]
    stories, _ = graph.build_storylines(findings)
    assert len(stories) == 1 and stories[0]["finding_count"] == 2


def test_unrelated_findings_stay_singletons():
    findings = [
        _f("a", ips=["1.1.1.1"]),
        _f("b", ips=["2.2.2.2"]),
        _f("c", ips=["3.3.3.3"]),
    ]
    stories, links = graph.build_storylines(findings)
    assert links == []
    assert len(stories) == 3


def test_severity_is_max_across_members():
    findings = [
        _f("a", sev="low", km={"core_hash": "x"}),
        _f("b", sev="critical", km={"core_hash": "x"}),
    ]
    stories, _ = graph.build_storylines(findings)
    assert stories[0]["severity"] == "critical"


def test_storyline_id_is_deterministic_and_order_independent():
    a = graph._story_id(["f1", "f2", "f3"])
    b = graph._story_id(["f3", "f1", "f2"])
    assert a == b and a.startswith("story_")


def test_seen_window_spans_members():
    findings = [
        _f("a", km={"core_hash": "x"}, first="2026-01-01", last="2026-02-01"),
        _f("b", km={"core_hash": "x"}, first="2025-12-01", last="2026-03-01"),
    ]
    stories, _ = graph.build_storylines(findings)
    assert stories[0]["first_seen"] == "2025-12-01"
    assert stories[0]["last_seen"] == "2026-03-01"


def test_empty_findings_yield_empty_outputs():
    stories, links = graph.build_storylines([])
    assert stories == [] and links == []
    # schema must still materialize a valid (empty) parquet table
    assert pa.Table.from_pylist(stories, schema=graph.STORYLINE_SCHEMA).num_rows == 0
    assert pa.Table.from_pylist(links, schema=graph.LINK_SCHEMA).num_rows == 0


def test_render_md_handles_zero_findings():
    # consolidation ratio is None with no findings — must not crash the :.2f
    summary = {"n_findings": 0, "n_storylines": 0, "n_multi_finding": 0,
               "finding_consolidation_ratio": None}
    md = graph._render_md([], summary)
    assert "consolidation ratio n/a" in md


def test_full_membership_overrides_sample_for_ip_links():
    # two findings whose 25-IP DISPLAY samples don't intersect, but whose full
    # member sets share an IP -> must fuse on the full set, not the sample.
    a = _f("a", ips=["1.1.1.1"])              # sample shows only 1.1.1.1
    b = _f("b", ips=["2.2.2.2"])              # sample shows only 2.2.2.2
    a["_full_ips"] = {"1.1.1.1", "9.9.9.9"}
    b["_full_ips"] = {"2.2.2.2", "9.9.9.9"}  # shared 9.9.9.9 only in full sets
    stories, links = graph.build_storylines([a, b])
    assert len(links) == 1
    assert len(stories) == 1 and stories[0]["finding_count"] == 2


def test_weight_count_cap_bounds_many_ip_overlap():
    shared = {"ip": [f"10.0.0.{i}" for i in range(1000)]}
    # capped at WEIGHT_COUNT_CAP, not 1000*3.0
    assert graph._edge_weight(shared) == graph.ENTITY_WEIGHTS["ip"] * graph.WEIGHT_COUNT_CAP

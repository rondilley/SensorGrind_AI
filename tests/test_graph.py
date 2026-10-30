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


def _d(fid, derived, **kw):
    f = _f(fid, **kw)
    f["_derived"] = derived
    return f


def test_shared_payload_fuses_findings_of_different_analyzers():
    # an HDC flag group and a LIF flag group about the same swarm share no
    # IP or fingerprint key, only the payload their members sent
    findings = [
        _d("hdc", {"payload": ["df3f6198"]}, pattern="neuro_hdc_group", ips=["1.1.1.1"]),
        _d("lif", {"payload": ["df3f6198"]}, pattern="neuro_lif_group", ips=["2.2.2.2"]),
    ]
    stories, links = graph.build_storylines(findings)
    assert len(links) == 1 and "payload" in json.loads(links[0]["shared"])
    assert [s["finding_count"] for s in stories] == [2]


def test_port_and_day_fuse_but_port_alone_does_not():
    alone = [_d("a", {"port": ["tcp/59618"]}), _d("b", {"port": ["tcp/59618"]})]
    assert graph.build_links(alone) == []
    both = [_d("a", {"port": ["tcp/59618"], "day": ["2025-08-16"]}),
            _d("b", {"port": ["tcp/59618"], "day": ["2025-08-16"]})]
    assert len(graph.build_links(both)) == 1


def test_l7_alone_does_not_fuse():
    findings = [_d("a", {"l7": ["bittorrent"]}), _d("b", {"l7": ["bittorrent"]})]
    assert graph.build_links(findings) == []


def test_derived_hub_value_is_dropped():
    n = graph.DERIVED_HUB_MAX_FINDINGS + 1
    findings = [_d(f"f{i}", {"payload": ["common"]}) for i in range(n)]
    assert graph.build_links(findings) == []
    findings = [_d(f"f{i}", {"payload": ["common"]}) for i in range(n - 1)]
    assert len(graph.build_links(findings)) == (n - 1) * (n - 2) // 2


def test_extract_entities_without_derived_has_empty_derived_types():
    e = graph.extract_entities(_f("a", ips=["1.1.1.1"]))
    assert all(e[t] == set() for t in graph.DERIVED_TYPES)


def test_pick_values_needs_share_and_two_members():
    counts = {"tcp/59618": 9, "tcp/22": 4, "tcp/80": 1}
    assert graph.pick_values(counts, 10) == ["tcp/59618"]
    # one-member finding: one member is enough
    assert graph.pick_values({"tcp/23": 1}, 1) == ["tcp/23"]
    # two of three members, but only one member has it -> not kept
    assert graph.pick_values({"x": 1}, 2) == []
    assert graph.pick_values({"x": 5}, 0) == []


def test_pick_values_caps_and_orders():
    counts = {f"v{i}": 10 - (i % 2) for i in range(8)}
    got = graph.pick_values(counts, 10)
    assert len(got) == graph.DERIVED_MAX_VALUES
    assert got[:4] == ["v0", "v2", "v4", "v6"]


def test_utc_day_converts_offsets():
    assert str(graph._utc_day("2025-08-16")) == "2025-08-16"
    assert str(graph._utc_day("2025-08-16 23:30:00-07:00")) == "2025-08-17"
    assert graph._utc_day("") is None and graph._utc_day("junk") is None


def test_derived_type_counts_once_per_edge():
    # two shared ports and an l7 label are still only corroboration
    findings = [_d("a", {"port": ["tcp/22", "tcp/2222"], "l7": ["ssh"]}),
                _d("b", {"port": ["tcp/22", "tcp/2222"], "l7": ["ssh"]})]
    assert graph.build_links(findings) == []
    # many shared days are one day
    findings = [_d("a", {"day": ["2025-07-06", "2025-07-07", "2025-07-08"]}),
                _d("b", {"day": ["2025-07-06", "2025-07-07", "2025-07-08"]})]
    assert graph.build_links(findings) == []


def test_ip_overlap_must_be_a_real_part_of_the_smaller_finding():
    big = [f"10.0.{i // 256}.{i % 256}" for i in range(1000)]
    a = _f("a", ips=big[:500])
    a["_full_ips"] = set(big[:500])
    b = _f("b", ips=big[499:])          # 1 shared IP of 500: chance
    b["_full_ips"] = set(big[499:])
    assert graph.build_links([a, b]) == []
    c = _f("c", ips=big[400:])          # 100 shared IPs: 20 % of 500
    c["_full_ips"] = set(big[400:])
    assert len(graph.build_links([a, c])) == 1


def test_tiny_finding_does_not_link_to_a_huge_one_on_one_ip():
    huge = {f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}" for i in range(15000)}
    a = _f("swarm"); a["_full_ips"] = huge
    b = _f("chain"); b["_full_ips"] = {"10.0.0.1", "192.0.2.1", "192.0.2.2", "192.0.2.3"}
    assert graph.build_links([a, b]) == []


def test_scanner_ips_do_not_link_findings():
    a = _f("a", ips=["198.51.100.7", "1.1.1.1"])
    b = _f("b", ips=["198.51.100.7", "2.2.2.2"])
    assert len(graph.build_links([a, b])) == 1
    assert graph.build_links([a, b], frozenset({"198.51.100.7"})) == []
    # the scanner stays in the storyline's IP list
    stories, _ = graph.build_storylines([a], frozenset({"198.51.100.7"}))
    assert "198.51.100.7" in stories[0]["src_ips_sample"]


def test_handshake_names_decode_text_or_show_hex():
    assert graph._pstr_name(b"BitTorrent protocol".hex()) == "BitTorrent protocol"
    assert graph._pstr_name("49020f57") == "custom 49020f57"
    assert graph._peer_prefix(b"-DL3790-".hex()) == "-DL3790-"
    assert graph._peer_prefix("0000005e") == "hex 0000005e"


def test_bt_facts_reads_the_handshakes_of_member_packets():
    import duckdb
    hs = (b"\x13" + b"BitTorrent protocol" + bytes(8) + bytes(range(20))
          + b"-qB4630-" + bytes(12))
    assert len(hs) == 68
    con = duckdb.connect()
    con.execute("CREATE TABLE hits (finding_id VARCHAR, src_ip VARCHAR, proto INT,"
                " dst_port INT, payload BLOB, l7_proto INT)")
    con.execute("CREATE TABLE payload_blobs (payload_sha256 BLOB, bytes BLOB,"
                " payload_len INT, l7_proto INT)")
    con.execute("INSERT INTO payload_blobs VALUES ('h1'::BLOB, ?, 68, ?)",
                [hs, graph.BT_L7_ID])
    for i in range(graph.BT_MIN_SOURCES):
        con.execute("INSERT INTO hits VALUES ('f1', ?, 6, 6881, 'h1'::BLOB, ?)",
                    [f"10.0.0.{i}", graph.BT_L7_ID])
    con.execute("INSERT INTO hits VALUES ('f2', '10.1.0.1', 6, 6881, 'h1'::BLOB, ?)",
                [graph.BT_L7_ID])
    out = graph.bt_facts(con, {"f1": 20, "f2": 1})
    assert set(out) == {"f1"}                       # f2 is under BT_MIN_SOURCES
    f1 = out["f1"]
    assert f1["handshake_sources"] == graph.BT_MIN_SOURCES
    assert f1["sampled_sources"] == 20 and f1["infohashes"] == 1
    assert f1["protocol_strings"] == [["BitTorrent protocol", graph.BT_MIN_SOURCES]]
    assert f1["peer_id_prefixes"] == [["-qB4630-", graph.BT_MIN_SOURCES]]
    assert f1["ports"] == [["tcp/6881", graph.BT_MIN_SOURCES]]


def test_storyline_carries_member_handshake_facts():
    a, b = _f("a", ips=["1.1.1.1"]), _f("b", ips=["1.1.1.1"])
    a["_bt"] = {"handshake_sources": 10}
    s = graph.assemble_storyline([a, b], [])
    assert json.loads(s["handshake_facts"]) == {"a": {"handshake_sources": 10}}
    assert graph.assemble_storyline([b], [])["handshake_facts"] is None


def test_bt_facts_needs_a_minimum_share_of_the_sample():
    import duckdb
    hs = b"\x13" + b"BitTorrent protocol" + bytes(28) + b"-qB4630-" + bytes(12)
    con = duckdb.connect()
    con.execute("CREATE TABLE hits (finding_id VARCHAR, src_ip VARCHAR, proto INT,"
                " dst_port INT, payload BLOB, l7_proto INT)")
    con.execute("CREATE TABLE payload_blobs (payload_sha256 BLOB, bytes BLOB,"
                " payload_len INT, l7_proto INT)")
    con.execute("INSERT INTO payload_blobs VALUES ('h1'::BLOB, ?, 68, ?)",
                [hs, graph.BT_L7_ID])
    for i in range(graph.BT_MIN_SOURCES):
        con.execute("INSERT INTO hits VALUES ('f1', ?, 6, 6881, 'h1'::BLOB, ?)",
                    [f"10.0.0.{i}", graph.BT_L7_ID])
    n = graph.BT_MIN_SOURCES
    assert "f1" in graph.bt_facts(con, {"f1": int(n / graph.BT_MIN_SHARE)})
    con.execute("DROP TABLE bt")
    assert graph.bt_facts(con, {"f1": int(n / graph.BT_MIN_SHARE) + 1}) == {}

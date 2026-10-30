"""correlate rule-registry contracts.

Pin that the HTTP-campaign rule (which consumes httppatterns cluster
membership) is registered and that the rule list stays well-formed. Rule
behavior on real data is exercised by running the stage; here we guard the
wiring so a rename/typo can't silently drop a rule.
"""
from __future__ import annotations

from conclusions import correlate


def test_http_campaign_rule_registered():
    assert correlate.pat_coordinated_http_campaign in correlate.PATTERNS


def test_all_patterns_are_callable_and_unique():
    assert all(callable(fn) for fn in correlate.PATTERNS)
    names = [fn.__name__ for fn in correlate.PATTERNS]
    assert len(names) == len(set(names)), "duplicate rule in PATTERNS"


def test_http_views_in_register_mapping():
    # the new views must be wired into _register_views so the rule can find them
    import inspect
    src = inspect.getsource(correlate._register_views)
    assert "http_clusters" in src and "http_templates" in src
    assert "l7_events" in src


def test_neuro_rules_registered_and_view_wired():
    import inspect
    assert correlate.pat_neuro_hdc_group in correlate.PATTERNS
    assert correlate.pat_neuro_lif_group in correlate.PATTERNS
    assert '"neuro"' in inspect.getsource(correlate._register_views)


def test_fact_rules_registered():
    for fn in (correlate.pat_miner_l7_offport, correlate.pat_landscape_new_top_port,
               correlate.pat_l7_protocol_surge):
        assert fn in correlate.PATTERNS


def test_std_port_map_uses_known_l7_names():
    from sg import lib
    assert set(correlate.L7_STD_PORTS) <= set(lib.L7_NAME.values())
    assert 59618 not in correlate.L7_STD_PORTS["bittorrent"]


def test_burst_chain_rule_registered():
    assert correlate.pat_burst_chain in correlate.PATTERNS


def test_bittorrent_sources_counts_group_members_per_day(monkeypatch):
    import datetime as dt
    import duckdb
    from sg import lib
    con = duckdb.connect()
    bt = lib.L7_ID["bittorrent"]
    con.execute(f"""CREATE VIEW pkt_view AS SELECT * FROM (VALUES
        (DATE '2025-09-28', '1.1.1.1', {bt}), (DATE '2025-09-28', '1.1.1.1', {bt}),
        (DATE '2025-09-28', '2.2.2.2', 0),    (DATE '2025-09-29', '2.2.2.2', {bt}),
        (DATE '2025-09-28', '9.9.9.9', {bt})) t(dt, src_ip, l7_proto)""")
    monkeypatch.setattr(correlate, "_REGISTERED", {"pkt_view"})
    d = dt.date(2025, 9, 28)
    rows = [(d, 2, ["1.1.1.1", "2.2.2.2"], [1.0, 0.5])]
    # 9.9.9.9 is not in the group; 2.2.2.2 sent BitTorrent only on another day
    assert correlate._bittorrent_sources(con, rows) == {d: 1}


def test_bittorrent_sources_without_packets_is_empty(monkeypatch):
    monkeypatch.setattr(correlate, "_REGISTERED", set())
    assert correlate._bittorrent_sources(None, [("d", 1, ["x"], [1.0])]) == {}

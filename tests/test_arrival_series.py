"""bench/arrival_series against the real corpus (Phase 2 minute vector).

One recorded day is built and checked against direct counts of the same
packets: the minute rows must add back up to the day, the port buckets
plus no_port must account for every packet, and new_src must equal the
sources whose corpus-wide first packet falls on that day.
"""
from __future__ import annotations

import datetime as _dt

import pytest

from bench import arrival_series as ars
from sg import lib

DAY = _dt.date(2024, 9, 10)          # development period (ARCHITECTURE §9.6)


def test_bucket_hash_spreads_common_ports():
    con = lib.duck()
    ports = [22, 23, 80, 443, 445, 3389, 8080]
    got = [con.execute(f"SELECT {ars.bucket_sql(str(p))}").fetchone()[0]
           for p in ports]
    assert all(0 <= b < ars.N_BUCKETS for b in got)
    assert len(set(got)) >= 6           # plain port % 16 puts 445 with 3389


@pytest.mark.corpus
def test_one_day_matches_direct_counts():
    con = lib.duck()
    lib.register_views(con)
    tab = ars.build(con, [DAY]).to_pydict()
    n_min = len(tab["minute"])
    assert 0 < n_min <= 1440
    pkts, no_port = con.execute(f"""
        SELECT count(*), count(*) FILTER (WHERE dst_port IS NULL)
        FROM packets WHERE dt = DATE '{DAY}' AND {ars.NOT_NTP}""").fetchone()
    assert sum(tab["pkts"]) == pkts
    assert sum(tab["no_port"]) == no_port
    assert sum(sum(tab[c]) for c in ars.BUCKET_COLS) + no_port == pkts
    t0 = _dt.datetime.combine(DAY, _dt.time(), _dt.timezone.utc)
    new = con.execute(f"""
        SELECT count(*) FROM (SELECT src_ip, min(ts) AS f FROM packets
                              WHERE {ars.NOT_NTP} GROUP BY src_ip)
        WHERE f >= TIMESTAMPTZ '{t0.isoformat()}'
          AND f <  TIMESTAMPTZ '{(t0 + _dt.timedelta(days=1)).isoformat()}'
    """).fetchone()[0]
    assert sum(tab["new_src"]) == new
    for i in range(n_min):
        assert tab["n_24"][i] <= tab["n_src"][i] <= tab["pkts"][i]
        assert 0.0 <= tab["syn_share"][i] <= 1.0

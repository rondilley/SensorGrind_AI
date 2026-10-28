#!/usr/bin/env python3
"""
bench/arrival_series — the per-minute global arrival vector for Phase 2.

One row per UTC minute that has packets, over the whole corpus (or a
``--start``/``--end`` slice).  NTP replies (UDP from port 123) are left
out, the same as sensormask: they answer the sensor's own NTP client and
are not Internet arrivals.  The sensor mask is NOT applied here; the
detectors drop masked minutes themselves (rule 1 of ARCHITECTURE §9.3).

Columns (ARCHITECTURE §9.6):
  pkts, n_src, n_24 (IPv4 /24 or IPv6 /48), new_src (sources whose first
  packet in the corpus falls in the minute), n_ports, syn_share, pay_pkts,
  no_port (no destination port: ICMP and others), pb00..pb15 (packets per
  destination-port hash bucket: one row of a Count-Min sketch, so the
  vector keeps a fixed width however many ports appear).

new_src always looks at the full corpus, so a slice gives the same values
as the full run for its minutes.  Days run one at a time; the only
corpus-wide pass is min(ts) per source (~1M groups).

Output: output/reports/arrival/arrival_series.{parquet,md}
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
import time
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib

N_BUCKETS = 16
BUCKET_COLS = [f"pb{i:02d}" for i in range(N_BUCKETS)]
COUNT_COLS = ["pkts", "n_src", "n_24", "new_src", "n_ports", "pay_pkts",
              "no_port"] + BUCKET_COLS

SERIES_SCHEMA = pa.schema(
    [("minute", pa.timestamp("us", tz="UTC"))]
    + [(c, pa.uint32()) for c in COUNT_COLS[:4]]
    + [("n_ports", pa.uint32()), ("syn_share", pa.float32())]
    + [(c, pa.uint32()) for c in COUNT_COLS[5:]])

NOT_NTP = "NOT (proto = 17 AND src_port IS NOT DISTINCT FROM 123)"


# ---------------------------------------------------------------- SQL helpers

def bucket_sql(col: str = "dst_port") -> str:
    """Knuth multiplicative hash of a 16-bit port, top 4 bits -> 0..15.
    Plain ``port % 16`` puts 445 and 3389 (and many service pairs) in one
    bucket; the multiplicative hash spreads neighbouring ports."""
    return f"((({col}::BIGINT * 40503) % 65536) // {65536 // N_BUCKETS})"


def prefix_sql(col: str = "src_ip") -> str:
    """IPv4 /24 (first three octets) or IPv6 /48 (first three groups)."""
    return (f"CASE WHEN contains({col}, ':') "
            f"THEN array_to_string(string_split({col}, ':')[1:3], ':') "
            f"ELSE regexp_extract({col}, '^(\\d+\\.\\d+\\.\\d+)\\.', 1) END")


def day_sql(day: _dt.date) -> str:
    buckets = ",\n".join(
        f"count(*) FILTER (WHERE b = {i})::UINTEGER AS {c}"
        for i, c in enumerate(BUCKET_COLS))
    return f"""
        WITH p AS (
            SELECT date_trunc('minute', ts) AS minute, src_ip, dst_port,
                   tcp_flags, payload_len,
                   CASE WHEN dst_port IS NULL THEN -1
                        ELSE {bucket_sql()} END AS b
            FROM packets
            WHERE dt = DATE '{day}' AND {NOT_NTP}
        ), m AS (
            SELECT minute,
                   count(*)::UINTEGER AS pkts,
                   count(DISTINCT src_ip)::UINTEGER AS n_src,
                   count(DISTINCT {prefix_sql()})::UINTEGER AS n_24,
                   count(DISTINCT dst_port)::UINTEGER AS n_ports,
                   avg(CASE WHEN tcp_flags = 2 THEN 1.0 ELSE 0.0 END)::FLOAT
                       AS syn_share,
                   count(*) FILTER (WHERE payload_len > 0)::UINTEGER AS pay_pkts,
                   count(*) FILTER (WHERE b = -1)::UINTEGER AS no_port,
                   {buckets}
            FROM p GROUP BY minute
        )
        SELECT m.minute, m.pkts, m.n_src, m.n_24,
               coalesce(f.new_src, 0)::UINTEGER AS new_src,
               m.n_ports, m.syn_share, m.pay_pkts, m.no_port,
               {", ".join("m." + c for c in BUCKET_COLS)}
        FROM m LEFT JOIN first_min f USING (minute)
        ORDER BY m.minute
    """


# ---------------------------------------------------------------- run

def build(con, days: list[_dt.date], log=sys.stderr) -> pa.Table:
    t0 = time.time()
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE first_min AS
        SELECT date_trunc('minute', first_ts) AS minute,
               count(*)::UINTEGER AS new_src
        FROM (SELECT src_ip, min(ts) AS first_ts FROM packets
              WHERE {NOT_NTP} GROUP BY src_ip)
        GROUP BY ALL
    """)
    print(f"[arrival] first-seen minutes in {time.time() - t0:.0f}s", file=log)
    parts = []
    for i, day in enumerate(days):
        parts.append(con.execute(day_sql(day)).to_arrow_table())
        if (i + 1) % 50 == 0 or i + 1 == len(days):
            print(f"[arrival] {i + 1}/{len(days)} days, "
                  f"{time.time() - t0:.0f}s", file=log)
    return pa.concat_tables(parts).cast(SERIES_SCHEMA)


def _markdown(tab: pa.Table, days: list[_dt.date]) -> str:
    import pyarrow.compute as pc
    lines = [f"- days: {len(days)} ({days[0]} to {days[-1]})" if days else
             "- days: 0",
             f"- minutes with packets: {tab.num_rows:,}",
             f"- packets (NTP replies left out): "
             f"{pc.sum(tab['pkts']).as_py() or 0:,}",
             f"- new sources: {pc.sum(tab['new_src']).as_py() or 0:,}",
             "", "| column | mean | max |", "| --- | ---: | ---: |"]
    for c in COUNT_COLS + ["syn_share"]:
        mm = pc.min_max(tab[c]).as_py()
        lines.append(f"| {c} | {pc.mean(tab[c]).as_py() or 0:.2f} | "
                     f"{mm['max'] or 0} |")
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck()
    lib.register_views(con)
    days = [r[0] for r in con.execute(
        "SELECT DISTINCT dt FROM packets ORDER BY dt").fetchall()]
    if args.start:
        days = [d for d in days if d >= args.start]
    if args.end:
        days = [d for d in days if d <= args.end]
    tab = build(con, days)
    con.close()
    rep = lib.Report(name="arrival", rows=tab, schema=SERIES_SCHEMA,
                     markdown=_markdown(tab, days))
    paths = rep.write(suffix=args.suffix)
    print(f"[arrival] wrote {paths['parquet']}", file=sys.stderr)
    return rep


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--start", type=_dt.date.fromisoformat)
    ap.add_argument("--end", type=_dt.date.fromisoformat)
    ap.add_argument("--suffix", default="series",
                    help="output stem arrival_<suffix> (default: series)")
    run(ap.parse_args())
    return 0


if __name__ == "__main__":
    sys.exit(main())

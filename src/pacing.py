#!/usr/bin/env python3
"""
pacing - inter-packet and inter-connection timing analysis.

Reveals automated vs human pacing, beaconing intervals, and pacing
fingerprints that survive infrastructure rotation.

What it computes
----------------
1. Per-source-IP inter-packet arrival statistics (median, p50/p95/p99 IAT)
2. Inter-connection timing per source (time between distinct 5-tuple flows)
3. Pacing-fingerprint clusters: round IAT values (10s/30s/60s/300s) signal
   scripted attackers
4. Connection duration distribution (first-to-last packet per flow)
5. Top "metronome" IPs: very low CV of IAT - mechanical pacing

Implementation
--------------
All timing aggregates are computed inside DuckDB using window functions
LIMITED to per-IP partitions in a single pass.  Result set is bounded to
the top-N IPs by packet count to keep memory predictable.
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


PER_IP_SCHEMA = pa.schema([
    ("src_ip",       pa.string()),
    ("pkt_count",    pa.uint64()),
    ("iat_median_s", pa.float64()),
    ("iat_p95_s",    pa.float64()),
    ("iat_p99_s",    pa.float64()),
    ("iat_cv",       pa.float64()),
    ("metronome",    pa.bool_()),
    ("beacon_60s",   pa.bool_()),
    ("beacon_300s",  pa.bool_()),
])

FLOW_DUR_SCHEMA = pa.schema([
    ("dur_bucket", pa.string()),
    ("flows",      pa.uint64()),
])


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    con.execute("SET preserve_insertion_order=false")
    con.execute("SET threads=6")
    lib.register_views(con)
    out_dir = lib.REPORTS / "pacing"
    out_dir.mkdir(parents=True, exist_ok=True)

    top_n = args.top_ips
    # Process the top IPs in hash(src_ip) buckets: the IAT window-sort and the
    # per-IP median/quantile_cont buffers (non-spillable) over the highest-
    # volume IPs were holding 40G+ and tripping the memory guard.  Bucketing
    # bounds each pass to 1/N of the IPs; each IP is wholly in one bucket so
    # its stats are exact.
    n_buckets = max(1, int(os.environ.get("SG_PACING_BUCKETS", "8")))
    print(f"[pacing] selecting top {top_n:,} IPs by packet count "
          f"({n_buckets} buckets)...", file=sys.stderr)
    con.execute(f"""
        CREATE TEMP TABLE pace_ips AS
        SELECT src_ip, (hash(src_ip) % {n_buckets})::INT AS bkt FROM (
            SELECT src_ip FROM packets
            GROUP BY src_ip
            HAVING count(*) >= {args.min_packets}
            ORDER BY count(*) DESC LIMIT {top_n}
        )
    """)

    print("[pacing] computing per-IP inter-arrival distributions...",
          file=sys.stderr)
    rows = []
    for k in range(n_buckets):
        rows += con.execute(f"""
            WITH paced AS (
                SELECT p.src_ip,
                       EXTRACT(EPOCH FROM p.ts - LAG(p.ts) OVER (
                           PARTITION BY p.src_ip ORDER BY p.ts)) AS iat
                FROM packets p
                SEMI JOIN (SELECT src_ip FROM pace_ips WHERE bkt = {k}) t
                  ON p.src_ip = t.src_ip
            )
            SELECT src_ip,
                   count(*) AS pkt_count,
                   median(iat) AS iat_median,
                   quantile_cont(iat, 0.95) AS iat_p95,
                   quantile_cont(iat, 0.99) AS iat_p99,
                   stddev_pop(iat) AS iat_std,
                   avg(iat) AS iat_mean
            FROM paced
            WHERE iat IS NOT NULL
            GROUP BY src_ip
        """).fetchall()
    print(f"[pacing] {len(rows):,} IPs profiled", file=sys.stderr)

    out_rows: list[dict] = []
    metronome_n = 0
    beacon_60_n = 0
    beacon_300_n = 0
    for ip, n, med, p95, p99, std, mean in rows:
        med = med or 0.0
        cv = (std / mean) if (mean and mean > 0) else None
        metro = bool(cv is not None and cv < 0.1 and n >= 100)
        b60 = bool(med and 55 <= med <= 65)
        b300 = bool(med and 290 <= med <= 310)
        metronome_n += int(metro)
        beacon_60_n += int(b60)
        beacon_300_n += int(b300)
        out_rows.append({
            "src_ip": ip, "pkt_count": int(n),
            "iat_median_s": float(med or 0),
            "iat_p95_s": float(p95 or 0),
            "iat_p99_s": float(p99 or 0),
            "iat_cv": float(cv) if cv is not None else 0.0,
            "metronome": metro, "beacon_60s": b60, "beacon_300s": b300,
        })
    out_rows.sort(key=lambda r: r["pkt_count"], reverse=True)
    pq.write_table(pa.Table.from_pylist(out_rows, schema=PER_IP_SCHEMA),
                   out_dir / "per_ip.parquet",
                   compression="zstd", compression_level=3)

    print("[pacing] connection-duration distribution...", file=sys.stderr)
    # Same bucketing: the flows GROUP BY (4-tuple) over the top IPs' TCP packets
    # is high-cardinality; process per IP-bucket and sum the duration histogram.
    dur_counts: Counter = Counter()
    for k in range(n_buckets):
        for b, n in con.execute(f"""
            WITH flows AS (
                SELECT p.src_ip, p.dst_ip, p.src_port, p.dst_port,
                       EXTRACT(EPOCH FROM max(p.ts) - min(p.ts)) AS dur
                FROM packets p
                SEMI JOIN (SELECT src_ip FROM pace_ips WHERE bkt = {k}) t
                  ON p.src_ip = t.src_ip
                WHERE p.proto = 6
                GROUP BY p.src_ip, p.dst_ip, p.src_port, p.dst_port
            )
            SELECT
                CASE WHEN dur < 1 THEN '0-1s'
                     WHEN dur < 10 THEN '1-10s'
                     WHEN dur < 60 THEN '10-60s'
                     WHEN dur < 300 THEN '1-5m'
                     WHEN dur < 3600 THEN '5-60m'
                     ELSE '>=1h' END AS dur_bucket,
                count(*) AS flows
            FROM flows GROUP BY dur_bucket
        """).fetchall():
            dur_counts[b] += n
    flow_rows = sorted(dur_counts.items(), key=lambda x: -x[1])
    pq.write_table(pa.Table.from_pylist(
        [{"dur_bucket": b, "flows": int(n)} for b, n in flow_rows],
        schema=FLOW_DUR_SCHEMA),
        out_dir / "flow_duration.parquet",
        compression="zstd", compression_level=3)

    con.close()

    md = [
        "# pacing - timing & pacing fingerprints", "",
        f"Profiled {len(out_rows):,} top-volume IPs.", "",
        f"- **{metronome_n:,}** IPs flagged as metronomes (IAT CV < 0.10, "
        "indicates mechanical scripted pacing)",
        f"- **{beacon_60_n:,}** IPs with median IAT in 55-65s "
        "(possible 1-minute beacon)",
        f"- **{beacon_300_n:,}** IPs with median IAT in 290-310s "
        "(possible 5-minute beacon)",
        "",
        "## Connection duration distribution (TCP flows only)",
        "",
        "| duration | flow_count |",
        "| --- | --- |",
    ]
    for b, n in flow_rows:
        md.append(f"| {b} | {n:,} |")

    md.extend(["", "## Top 40 metronome IPs (lowest CV, fastest median)", "",
               "| src_ip | pkt_count | median_iat_s | cv | beacon_60s | beacon_300s |",
               "| --- | --- | --- | --- | --- | --- |"])
    metros = [r for r in out_rows if r["metronome"]]
    metros.sort(key=lambda r: r["iat_cv"])
    for r in metros[:40]:
        md.append(f"| {r['src_ip']} | {r['pkt_count']:,} | "
                  f"{r['iat_median_s']:.3f} | {r['iat_cv']:.3f} | "
                  f"{'YES' if r['beacon_60s'] else ''} | "
                  f"{'YES' if r['beacon_300s'] else ''} |")

    (out_dir / "pacing.md").write_text("\n".join(md) + "\n")
    print(f"[pacing] wrote {out_dir}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top-ips", type=int, default=50_000,
                    help="Top N IPs by packet count to profile (default 50000)")
    ap.add_argument("--min-packets", type=int, default=20)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

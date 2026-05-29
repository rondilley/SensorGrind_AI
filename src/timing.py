#!/usr/bin/env python3
"""
timing — per-source-IP timing patterns and burstiness analysis.

Computes hourly packet-rate variability per source IP to distinguish
automated scanning (consistent rate across hours) from human-driven
or bursty activity. Also identifies each IP's peak activity hour
in UTC for timezone inference.

Implementation note: we aggregate to per-(IP, hour) buckets entirely
in DuckDB rather than using a row-level LAG window function — the
latter would materialize 1B+ intermediate rows.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("src_ip",          pa.string()),
    ("pkt_count",       pa.uint64()),
    ("active_hours",    pa.uint32()),
    ("day_count",       pa.uint16()),
    ("first_seen",      pa.timestamp("us", tz="UTC")),
    ("last_seen",       pa.timestamp("us", tz="UTC")),
    ("hourly_mean",     pa.float32()),
    ("hourly_stddev",   pa.float32()),
    ("burstiness_cv",   pa.float32()),
    ("peak_hour_utc",   pa.uint8()),
    ("automated",       pa.bool_()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    min_pkts = 20
    print("[timing] aggregating per-IP per-hour buckets...", file=sys.stderr)
    rows = con.execute(f"""
        WITH hourly AS (
            SELECT src_ip,
                   date_trunc('hour', ts)  AS hr,
                   EXTRACT(HOUR FROM ts)   AS hod,
                   count(*)                AS pkts
            FROM packets
            WHERE {where}
            GROUP BY src_ip, hr, hod
        )
        SELECT src_ip,
               sum(pkts)                              AS pkt_count,
               count(*)                               AS active_hours,
               count(DISTINCT CAST(hr AS DATE))       AS day_count,
               min(hr)                                AS first_seen,
               max(hr)                                AS last_seen,
               avg(pkts)                              AS hourly_mean,
               coalesce(stddev_pop(pkts), 0)          AS hourly_stddev,
               mode(hod)                              AS peak_hour_utc
        FROM hourly
        GROUP BY src_ip
        HAVING sum(pkts) >= {min_pkts}
        ORDER BY pkt_count DESC
    """).fetchall()
    print(f"[timing] {len(rows):,} IPs with {min_pkts}+ packets", file=sys.stderr)
    con.close()

    results: list[dict] = []
    auto_count = 0
    hour_dist: dict[int, int] = defaultdict(int)

    for r in rows:
        ip = r[0]
        if not lib.is_real_external_ip(ip):
            continue
        pkt_count = int(r[1])
        active_hours = int(r[2])
        day_count = int(r[3])
        first_seen = r[4]
        last_seen = r[5]
        h_mean = float(r[6] or 0)
        h_std = float(r[7] or 0)
        cv = h_std / h_mean if h_mean > 0 else 999.0
        peak_hour = int(r[8]) if r[8] is not None else 0
        # automated: consistent rate (low CV), spanning many hours
        automated = cv < 0.5 and active_hours >= 5

        if automated:
            auto_count += 1
        hour_dist[peak_hour] += 1

        results.append({
            "src_ip": ip, "pkt_count": pkt_count, "active_hours": active_hours,
            "day_count": day_count, "first_seen": first_seen, "last_seen": last_seen,
            "hourly_mean": h_mean, "hourly_stddev": h_std,
            "burstiness_cv": cv if cv < 1000 else 0.0,
            "peak_hour_utc": peak_hour, "automated": automated,
        })

    top_n = args.limit or 40
    md = f"""## Summary

- **{len(results):,}** IPs analyzed (≥{min_pkts} packets)
- **{auto_count:,}** classified as automated (low hourly-rate CV, ≥5 active hours)

## Peak activity hours (UTC)

"""
    md += lib.markdown_table(
        [{"hour_utc": h, "ip_count": hour_dist[h]} for h in range(24) if hour_dist[h]],
        columns=["hour_utc", "ip_count"])
    md += f"\n## Top {top_n} most automated sources\n\n"
    auto_results = [r for r in results if r["automated"]]
    auto_results.sort(key=lambda r: r["pkt_count"], reverse=True)
    md += lib.markdown_table(auto_results[:top_n],
        columns=["src_ip", "pkt_count", "active_hours", "day_count",
                 "burstiness_cv", "peak_hour_utc"])

    return lib.Report(name="timing", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[timing] wrote {paths['parquet']}")
    print(f"[timing] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

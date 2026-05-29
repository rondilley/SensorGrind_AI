#!/usr/bin/env python3
"""
campaign — cluster attackers by shared payload hashes within time windows.

IPs that send the same payload SHA-256 are likely operated by the same
actor or botnet. Groups IPs into campaigns using payload overlap,
then enriches with timing and geo metadata.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("campaign_id",     pa.uint32()),
    ("payload_sha256",  pa.binary(32)),
    ("ip_count",        pa.uint32()),
    ("total_hits",      pa.uint64()),
    ("first_seen",      pa.timestamp("us", tz="UTC")),
    ("last_seen",       pa.timestamp("us", tz="UTC")),
    ("day_count",       pa.uint16()),
    ("sample_ips",      pa.string()),
    ("l7_proto",        pa.string()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    min_ips = 3

    # Pass 1: aggregate without list() (which can blow memory on hot groups).
    print("[campaign] finding shared payloads across IPs (pass 1)...", file=sys.stderr)
    rows = con.execute(f"""
        SELECT payload_sha256, l7_proto,
               count(DISTINCT src_ip) AS ip_count,
               count(*)                AS total_hits,
               min(ts)                 AS first_seen,
               max(ts)                 AS last_seen,
               count(DISTINCT dt)      AS day_count
        FROM packets
        WHERE payload_sha256 IS NOT NULL AND payload_len > 0 AND {where}
        GROUP BY payload_sha256, l7_proto
        HAVING count(DISTINCT src_ip) >= {min_ips}
        ORDER BY ip_count DESC
        LIMIT 5000
    """).fetchall()
    print(f"[campaign] {len(rows):,} payloads shared by {min_ips}+ IPs", file=sys.stderr)

    # Pass 2: fetch sample IPs only for the surviving payloads.
    print("[campaign] fetching sample IPs for each campaign...", file=sys.stderr)
    sha_to_samples: dict[bytes, list[str]] = {}
    if rows:
        con.execute("CREATE TEMP TABLE camp_sha (sha BLOB)")
        for r in rows:
            con.execute("INSERT INTO camp_sha VALUES (?)", [r[0]])
        sample_rows = con.execute(f"""
            WITH ranked AS (
                SELECT p.payload_sha256, p.src_ip,
                       row_number() OVER (PARTITION BY p.payload_sha256 ORDER BY p.src_ip) AS rn
                FROM packets p
                JOIN camp_sha c ON p.payload_sha256 = c.sha
                WHERE {where}
                GROUP BY p.payload_sha256, p.src_ip
            )
            SELECT payload_sha256, src_ip FROM ranked WHERE rn <= 10
        """).fetchall()
        for sha, ip in sample_rows:
            sha_to_samples.setdefault(sha, []).append(ip)
    con.close()

    results: list[dict] = []
    for i, r in enumerate(rows):
        samples = sha_to_samples.get(r[0], [])
        results.append({
            "campaign_id": i, "payload_sha256": r[0],
            "ip_count": r[2], "total_hits": r[3],
            "first_seen": r[4], "last_seen": r[5], "day_count": r[6],
            "sample_ips": ", ".join(samples),
            "l7_proto": lib.L7_NAME.get(r[1], "unknown"),
        })

    top_n = args.limit or 40
    top_ips = results[0]["ip_count"] if results else 0
    md = f"""## Summary

- **{len(results):,}** campaigns (payloads shared by {min_ips}+ distinct source IPs)
- Top campaign has **{top_ips:,}** distinct IPs

## Top {top_n} campaigns by IP count

"""
    md += lib.markdown_table(results[:top_n],
        columns=["campaign_id", "ip_count", "total_hits", "day_count", "l7_proto", "sample_ips"])

    return lib.Report(name="campaign", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[campaign] wrote {paths['parquet']}")
    print(f"[campaign] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

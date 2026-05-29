#!/usr/bin/env python3
"""
rdpbrute — detect RDP brute-force campaigns via mstshash cookies.

Extracts mstshash cookies from the iocs table and credential pairs.
Groups by cookie value to identify actors and credential lists,
and tracks campaign timing.
"""
from __future__ import annotations

import argparse
import sys

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("mstshash",      pa.string()),
    ("src_ip_count",  pa.uint32()),
    ("hit_count",     pa.uint64()),
    ("first_seen",    pa.timestamp("us", tz="UTC")),
    ("last_seen",     pa.timestamp("us", tz="UTC")),
    ("day_count",     pa.uint16()),
    ("sample_srcs",   pa.string()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[rdpbrute] querying mstshash cookies...", file=sys.stderr)
    msts = con.execute(f"""
        SELECT
            value, count(DISTINCT src_ip) AS src_ip_count,
            count(*) AS hit_count, min(ts) AS first_seen, max(ts) AS last_seen,
            count(DISTINCT dt) AS day_count,
            list(DISTINCT src_ip ORDER BY src_ip)[:5] AS sample_srcs
        FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['mstshash']} AND {where}
        GROUP BY value ORDER BY src_ip_count DESC
    """).fetchall()
    print(f"[rdpbrute] {len(msts):,} distinct mstshash cookies", file=sys.stderr)

    print("[rdpbrute] querying credential pairs...", file=sys.stderr)
    creds = con.execute(f"""
        SELECT value, count(DISTINCT src_ip) AS src_ip_count,
               count(*) AS hit_count, min(ts) AS first_seen, max(ts) AS last_seen
        FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['cred']} AND {where}
        GROUP BY value ORDER BY src_ip_count DESC
    """).fetchall()
    print(f"[rdpbrute] {len(creds):,} distinct credential pairs", file=sys.stderr)

    rdp_ips = con.execute(f"""
        SELECT count(DISTINCT src_ip) FROM packets
        WHERE dst_port = 3389 AND proto = 6 AND {where}
    """).fetchone()[0]
    con.close()

    results = [{
        "mstshash": r[0], "src_ip_count": r[1], "hit_count": r[2],
        "first_seen": r[3], "last_seen": r[4], "day_count": r[5],
        "sample_srcs": ", ".join(r[6]) if r[6] else "",
    } for r in msts]

    top_n = args.limit or 40
    md = f"""## Summary

- **{rdp_ips:,}** unique IPs targeted port 3389
- **{len(msts):,}** distinct mstshash cookie values
- **{len(creds):,}** distinct credential pairs observed

## Top {top_n} mstshash cookies (by source IP spread)

"""
    md += lib.markdown_table(results[:top_n],
        columns=["mstshash", "src_ip_count", "hit_count", "day_count", "sample_srcs"])
    md += f"\n## Top {top_n} credential pairs\n\n"
    md += lib.markdown_table(
        [{"credential": c[0], "src_ip_count": c[1], "hit_count": c[2]} for c in creds[:top_n]],
        columns=["credential", "src_ip_count", "hit_count"])

    return lib.Report(name="rdpbrute", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[rdpbrute] wrote {paths['parquet']}")
    print(f"[rdpbrute] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

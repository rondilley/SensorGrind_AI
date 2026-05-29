#!/usr/bin/env python3
"""
droppers — extract and rank dropper/loader IOCs.

Mines the iocs table for wget/curl/tftp commands, dropper URLs,
and payload hashes observed in Mirai-style and other IoT malware
delivery chains. Groups by dropper infrastructure (domain/IP of
the payload server) and tracks emergence over time.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from urllib.parse import urlparse

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("value",         pa.string()),
    ("ioc_kind",      pa.string()),
    ("host",          pa.string()),
    ("src_ip_count",  pa.uint32()),
    ("hit_count",     pa.uint64()),
    ("first_seen",    pa.timestamp("us", tz="UTC")),
    ("last_seen",     pa.timestamp("us", tz="UTC")),
    ("day_count",     pa.uint16()),
    ("sample_srcs",   pa.string()),
])


def _extract_host(value: str) -> str:
    try:
        p = urlparse(value)
        if p.hostname:
            return p.hostname
    except Exception:
        pass
    m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', value)
    if m:
        return m.group(1)
    return ""


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    dropper_kinds = [lib.IOC_ID["url"], lib.IOC_ID["cmd"]]
    kind_list = ",".join(str(k) for k in dropper_kinds)

    print("[droppers] querying dropper IOCs...", file=sys.stderr)
    rows = con.execute(f"""
        SELECT
            value,
            ioc_kind,
            count(DISTINCT src_ip)  AS src_ip_count,
            count(*)                AS hit_count,
            min(ts)                 AS first_seen,
            max(ts)                 AS last_seen,
            count(DISTINCT dt)      AS day_count,
            list(DISTINCT src_ip ORDER BY src_ip)[:5] AS sample_srcs
        FROM iocs
        WHERE ioc_kind IN ({kind_list}) AND {where}
        GROUP BY value, ioc_kind
        ORDER BY src_ip_count DESC
    """).fetchall()
    print(f"[droppers] {len(rows):,} distinct dropper IOCs", file=sys.stderr)

    con.close()

    results: list[dict] = []
    host_counts: dict[str, int] = defaultdict(int)

    for r in rows:
        value, kind, src_count, hits, first, last, days, samples = r
        host = _extract_host(value)
        host_counts[host] += 1
        results.append({
            "value": value[:512], "ioc_kind": lib.IOC_NAME.get(kind, str(kind)),
            "host": host, "src_ip_count": src_count, "hit_count": hits,
            "first_seen": first, "last_seen": last, "day_count": days,
            "sample_srcs": ", ".join(samples) if samples else "",
        })

    top_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:30]
    top_n = args.limit or 40

    md = f"""## Summary

- **{len(results):,}** distinct dropper IOCs (URLs + commands)
- **{len(host_counts):,}** distinct dropper hosts/IPs

## Top dropper infrastructure (by IOC count)

"""
    md += lib.markdown_table(
        [{"host": h, "ioc_count": c} for h, c in top_hosts],
        columns=["host", "ioc_count"],
    )
    md += f"\n## Top {top_n} dropper IOCs by source IP spread\n\n"
    md += lib.markdown_table(
        results[:top_n],
        columns=["value", "ioc_kind", "host", "src_ip_count", "hit_count", "day_count"],
    )

    print(f"[droppers] {len(results):,} IOCs, {len(host_counts):,} hosts", file=sys.stderr)
    return lib.Report(name="droppers", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[droppers] wrote {paths['parquet']}")
    print(f"[droppers] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

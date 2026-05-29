#!/usr/bin/env python3
"""
cveseries — longitudinal time series of CVE probe activity.

Reads probesigs output and builds per-CVE/probe-tag daily time series
showing emergence, peak, and decay of exploit scanning campaigns.
"""
from __future__ import annotations

import argparse
import sys

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("probe_tag",    pa.string()),
    ("date",         pa.string()),
    ("hit_count",    pa.uint64()),
    ("src_ip_count", pa.uint32()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    probesigs_path = lib.REPORTS / "probesigs" / "probesigs.parquet"
    if not probesigs_path.exists() or probesigs_path.stat().st_size == 0:
        print("[cveseries] probesigs output not found — run probesigs first", file=sys.stderr)
        return lib.Report(name="cveseries", rows=[], schema=RESULT_SCHEMA,
                          markdown="probesigs output not found. Run probesigs first.\n")

    # Get the URI→tag mapping from probesigs
    print("[cveseries] loading probe tag mappings...", file=sys.stderr)
    tag_map = {}
    probes = con.execute(f"""
        SELECT uri, probe_tag FROM read_parquet('{probesigs_path}')
    """).fetchall()
    for uri, tag in probes:
        tag_map[uri] = tag

    # Build daily series from iocs (http_uri) joined with tag map
    print("[cveseries] building daily time series...", file=sys.stderr)
    uri_daily = con.execute(f"""
        SELECT value AS uri, CAST(ts AS DATE) AS date,
               count(*) AS hit_count, count(DISTINCT src_ip) AS src_ip_count
        FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['http_uri']} AND {where}
        GROUP BY value, CAST(ts AS DATE)
    """).fetchall()
    con.close()

    results: list[dict] = []
    tag_totals: dict[str, int] = {}
    for r in uri_daily:
        uri, date, hits, ips = r
        tag = tag_map.get(uri)
        if not tag:
            continue
        results.append({
            "probe_tag": tag, "date": str(date),
            "hit_count": hits, "src_ip_count": ips,
        })
        tag_totals[tag] = tag_totals.get(tag, 0) + hits

    results.sort(key=lambda r: (r["probe_tag"], r["date"]))
    tag_summary = sorted(tag_totals.items(), key=lambda x: x[1], reverse=True)

    md = f"""## Summary

- **{len(tag_totals):,}** probe tags tracked over time
- **{len(results):,}** daily data points

## Probe tags by total volume

"""
    md += lib.markdown_table(
        [{"probe_tag": t, "total_hits": c} for t, c in tag_summary],
        columns=["probe_tag", "total_hits"])

    print(f"[cveseries] {len(results):,} daily data points across {len(tag_totals):,} tags",
          file=sys.stderr)
    return lib.Report(name="cveseries", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[cveseries] wrote {paths['parquet']}")
    print(f"[cveseries] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

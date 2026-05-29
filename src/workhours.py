#!/usr/bin/env python3
"""
workhours — global temporal heatmaps and weekday/weekend patterns.

Aggregates all traffic by hour-of-day and day-of-week to reveal
temporal patterns: business-hours scanning vs 24/7 botnets,
weekend drops, and regional activity peaks.
"""
from __future__ import annotations

import argparse
import sys

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("dow",         pa.uint8()),
    ("hour_utc",    pa.uint8()),
    ("pkt_count",   pa.uint64()),
    ("ip_count",    pa.uint32()),
    ("l7_events",   pa.uint32()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[workhours] building temporal heatmap from packets...", file=sys.stderr)
    rows = con.execute(f"""
        SELECT EXTRACT(DOW FROM ts) AS dow,
               EXTRACT(HOUR FROM ts) AS hour_utc,
               count(*) AS pkt_count,
               count(DISTINCT src_ip) AS ip_count
        FROM packets
        WHERE {where}
        GROUP BY dow, hour_utc
        ORDER BY dow, hour_utc
    """).fetchall()

    l7_rows = con.execute(f"""
        SELECT EXTRACT(DOW FROM ts) AS dow,
               EXTRACT(HOUR FROM ts) AS hour_utc,
               count(*) AS l7_events
        FROM l7_events
        WHERE {where}
        GROUP BY dow, hour_utc
    """).fetchall()
    l7_map = {(int(r[0]), int(r[1])): r[2] for r in l7_rows}
    con.close()

    results = [{
        "dow": int(r[0]), "hour_utc": int(r[1]), "pkt_count": r[2],
        "ip_count": r[3], "l7_events": l7_map.get((int(r[0]), int(r[1])), 0),
    } for r in rows]

    dow_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    dow_totals = {}
    for r in results:
        d = r["dow"]
        dow_totals[d] = dow_totals.get(d, 0) + r["pkt_count"]

    md = """## Packets by day of week

"""
    md += lib.markdown_table(
        [{"day": dow_names[d], "packets": c} for d, c in sorted(dow_totals.items())],
        columns=["day", "packets"])

    md += "\n## Heatmap (packets per hour-of-day × day-of-week)\n\n"
    md += "| Hour |"
    for d in range(7):
        md += f" {dow_names[d]} |"
    md += "\n| --- |" + " --- |" * 7 + "\n"
    grid = {}
    for r in results:
        grid[(r["dow"], r["hour_utc"])] = r["pkt_count"]
    for h in range(24):
        md += f"| {h:02d} |"
        for d in range(7):
            v = grid.get((d, h), 0)
            md += f" {v:,} |"
        md += "\n"

    print(f"[workhours] {len(results):,} hour×day cells", file=sys.stderr)
    return lib.Report(name="workhours", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[workhours] wrote {paths['parquet']}")
    print(f"[workhours] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

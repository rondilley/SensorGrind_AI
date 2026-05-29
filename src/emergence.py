#!/usr/bin/env python3
"""
emergence — surface new ports, new IPs, and new IOCs appearing recently.

Compares the most recent window (default: last 7 days of data) against
the historical baseline to find first-time-seen ports, IPs, user-agents,
and dropper URLs. Useful for early warning of new campaigns.
"""
from __future__ import annotations

import argparse
import sys

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("entity_type",  pa.string()),
    ("value",        pa.string()),
    ("first_seen",   pa.timestamp("us", tz="UTC")),
    ("hit_count",    pa.uint64()),
    ("src_ip_count", pa.uint32()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    print("[emergence] finding data time range...", file=sys.stderr)
    max_date = con.execute("SELECT max(ts)::DATE FROM packets").fetchone()[0]
    window_days = 7
    cutoff = max_date - __import__("datetime").timedelta(days=window_days)
    print(f"[emergence] recent window: {cutoff} to {max_date}", file=sys.stderr)

    results: list[dict] = []

    # New destination ports
    print("[emergence] finding new destination ports...", file=sys.stderr)
    new_ports = con.execute(f"""
        WITH recent AS (
            SELECT DISTINCT dst_port FROM packets WHERE ts >= '{cutoff}' AND dst_port IS NOT NULL
        ),
        historical AS (
            SELECT DISTINCT dst_port FROM packets WHERE ts < '{cutoff}' AND dst_port IS NOT NULL
        )
        SELECT r.dst_port, min(p.ts) AS first_seen, count(*) AS hit_count,
               count(DISTINCT p.src_ip) AS src_ip_count
        FROM recent r
        LEFT JOIN historical h ON r.dst_port = h.dst_port
        JOIN packets p ON p.dst_port = r.dst_port AND p.ts >= '{cutoff}'
        WHERE h.dst_port IS NULL
        GROUP BY r.dst_port ORDER BY src_ip_count DESC
    """).fetchall()
    for r in new_ports:
        results.append({"entity_type": "dst_port", "value": str(r[0]),
                        "first_seen": r[1], "hit_count": r[2], "src_ip_count": r[3]})

    # New source IPs
    print("[emergence] finding new source IPs...", file=sys.stderr)
    new_ips = con.execute(f"""
        WITH recent AS (SELECT DISTINCT src_ip FROM packets WHERE ts >= '{cutoff}'),
             historical AS (SELECT DISTINCT src_ip FROM packets WHERE ts < '{cutoff}')
        SELECT r.src_ip, min(p.ts) AS first_seen, count(*) AS hit_count
        FROM recent r
        LEFT JOIN historical h ON r.src_ip = h.src_ip
        JOIN packets p ON p.src_ip = r.src_ip AND p.ts >= '{cutoff}'
        WHERE h.src_ip IS NULL
        GROUP BY r.src_ip ORDER BY hit_count DESC LIMIT 200
    """).fetchall()
    for r in new_ips:
        results.append({"entity_type": "src_ip", "value": r[0],
                        "first_seen": r[1], "hit_count": r[2], "src_ip_count": 1})

    # New IOC values (URLs, user-agents)
    print("[emergence] finding new IOC values...", file=sys.stderr)
    for kind_name in ("url", "user_agent", "ssh_banner"):
        kind_id = lib.IOC_ID[kind_name]
        new_iocs = con.execute(f"""
            WITH recent AS (SELECT DISTINCT value FROM iocs WHERE ioc_kind={kind_id} AND ts >= '{cutoff}'),
                 historical AS (SELECT DISTINCT value FROM iocs WHERE ioc_kind={kind_id} AND ts < '{cutoff}')
            SELECT r.value, min(i.ts) AS first_seen, count(*) AS hit_count,
                   count(DISTINCT i.src_ip) AS src_ip_count
            FROM recent r
            LEFT JOIN historical h ON r.value = h.value
            JOIN iocs i ON i.value = r.value AND i.ioc_kind={kind_id} AND i.ts >= '{cutoff}'
            WHERE h.value IS NULL
            GROUP BY r.value ORDER BY src_ip_count DESC LIMIT 100
        """).fetchall()
        for r in new_iocs:
            results.append({"entity_type": kind_name, "value": r[0][:512],
                            "first_seen": r[1], "hit_count": r[2], "src_ip_count": r[3]})

    con.close()

    type_counts = {}
    for r in results:
        t = r["entity_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    top_n = args.limit or 40
    md = f"""## Emergence report: {cutoff} to {max_date}

### New entities by type

"""
    md += lib.markdown_table(
        [{"type": t, "count": c} for t, c in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)],
        columns=["type", "count"])

    for etype in ("dst_port", "src_ip", "url", "user_agent", "ssh_banner"):
        subset = [r for r in results if r["entity_type"] == etype]
        if subset:
            md += f"\n### New {etype} ({len(subset):,})\n\n"
            md += lib.markdown_table(subset[:top_n],
                columns=["value", "first_seen", "hit_count", "src_ip_count"])

    print(f"[emergence] {len(results):,} new entities found", file=sys.stderr)
    return lib.Report(name="emergence", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[emergence] wrote {paths['parquet']}")
    print(f"[emergence] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

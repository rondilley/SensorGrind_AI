#!/usr/bin/env python3
"""
scannerintel — per-IP dossier combining all available signals.

Joins packets, iocs, and benignfilter output to build a comprehensive
profile for each source IP: ports hit, protocols, timing, geo, ASN,
user-agents, known-benign status, and top IOCs.
"""
from __future__ import annotations

import argparse
import sys

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("src_ip",        pa.string()),
    ("pkt_count",     pa.uint64()),
    ("port_count",    pa.uint32()),
    ("l7_events",     pa.uint32()),
    ("ioc_count",     pa.uint32()),
    ("day_count",     pa.uint16()),
    ("first_seen",    pa.timestamp("us", tz="UTC")),
    ("last_seen",     pa.timestamp("us", tz="UTC")),
    ("top_port",      pa.uint16()),
    ("l7_dominant",   pa.string()),
    ("benign_org",    pa.string()),
    ("country_iso",   pa.string()),
    ("asn",           pa.uint32()),
    ("asn_org",       pa.string()),
    ("top_ua",        pa.string()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    benign_path = lib.REPORTS / "benignfilter" / "benignfilter.parquet"
    has_benign = benign_path.exists() and benign_path.stat().st_size > 0

    print("[scannerintel] building per-IP dossiers...", file=sys.stderr)
    rows = con.execute(f"""
        WITH pkt_agg AS (
            SELECT src_ip, count(*) AS pkt_count,
                   count(DISTINCT dst_port) AS port_count,
                   count(DISTINCT dt) AS day_count,
                   min(ts) AS first_seen, max(ts) AS last_seen,
                   mode(dst_port) AS top_port, mode(l7_proto) AS l7_mode
            FROM packets WHERE {where} GROUP BY src_ip
        ),
        l7_agg AS (
            SELECT src_ip, count(*) AS l7_events FROM l7_events WHERE {where} GROUP BY src_ip
        ),
        ioc_agg AS (
            SELECT src_ip, count(*) AS ioc_count FROM iocs WHERE {where} GROUP BY src_ip
        ),
        ua_agg AS (
            SELECT src_ip, mode(value) AS top_ua FROM iocs
            WHERE ioc_kind = {lib.IOC_ID['user_agent']} AND {where} GROUP BY src_ip
        )
        SELECT p.src_ip, p.pkt_count, p.port_count,
               COALESCE(l.l7_events, 0), COALESCE(i.ioc_count, 0),
               p.day_count, p.first_seen, p.last_seen,
               p.top_port, p.l7_mode,
               u.top_ua
        FROM pkt_agg p
        LEFT JOIN l7_agg l ON p.src_ip = l.src_ip
        LEFT JOIN ioc_agg i ON p.src_ip = i.src_ip
        LEFT JOIN ua_agg u ON p.src_ip = u.src_ip
        ORDER BY p.pkt_count DESC
    """).fetchall()
    print(f"[scannerintel] {len(rows):,} IPs profiled", file=sys.stderr)

    benign_map: dict[str, str] = {}
    if has_benign:
        bf = con.execute(f"""
            SELECT src_ip, org FROM read_parquet('{benign_path}')
        """).fetchall()
        benign_map = {r[0]: r[1] for r in bf}
    con.close()

    geo = lib.GeoLookup()
    results: list[dict] = []
    for r in rows:
        ip = r[0]
        if not lib.is_real_external_ip(ip):
            continue
        geo_rec = geo.lookup(ip)
        results.append({
            "src_ip": ip, "pkt_count": r[1], "port_count": r[2],
            "l7_events": r[3], "ioc_count": r[4], "day_count": r[5],
            "first_seen": r[6], "last_seen": r[7],
            "top_port": r[8], "l7_dominant": lib.L7_NAME.get(r[9], "unknown"),
            "benign_org": benign_map.get(ip, ""),
            "country_iso": geo_rec.country_iso, "asn": geo_rec.asn,
            "asn_org": geo_rec.asn_org, "top_ua": r[10] or "",
        })
    geo.close()

    top_n = args.limit or 50
    md = f"""## Summary

- **{len(results):,}** unique source IPs profiled
- **{sum(1 for r in results if r['benign_org']):,}** tagged as known-benign

## Top {top_n} IPs by packet volume

"""
    md += lib.markdown_table(results[:top_n],
        columns=["src_ip", "pkt_count", "port_count", "day_count", "l7_dominant",
                 "benign_org", "country_iso", "asn_org"])

    return lib.Report(name="scannerintel", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[scannerintel] wrote {paths['parquet']}")
    print(f"[scannerintel] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

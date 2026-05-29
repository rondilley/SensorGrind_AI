#!/usr/bin/env python3
"""
portscans — detect horizontal/vertical port scans and sweeps.

Horizontal: one IP hits many ports on the sensor (reconnaissance).
Vertical: one IP hits one port across many days (persistence/service probe).

Classifies scan type from TCP flag patterns:
  SYN scan (flags=S), connect scan (flags=SA), FIN/Xmas/NULL stealth scans.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("src_ip",        pa.string()),
    ("scan_type",     pa.string()),
    ("port_count",    pa.uint32()),
    ("pkt_count",     pa.uint64()),
    ("day_count",     pa.uint16()),
    ("top_ports",     pa.string()),
    ("flag_profile",  pa.string()),
    ("first_seen",    pa.timestamp("us", tz="UTC")),
    ("last_seen",     pa.timestamp("us", tz="UTC")),
    ("country_iso",   pa.string()),
    ("asn",           pa.uint32()),
    ("asn_org",       pa.string()),
])


def _classify_flags(syn_pct: float, fin_pct: float, null_pct: float, xmas_pct: float) -> str:
    if xmas_pct > 0.3:
        return "xmas_scan"
    if null_pct > 0.3:
        return "null_scan"
    if fin_pct > 0.3:
        return "fin_scan"
    if syn_pct > 0.7:
        return "syn_scan"
    return "connect_scan"


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    min_ports = 10

    print("[portscans] identifying scanners...", file=sys.stderr)
    rows = con.execute(f"""
        WITH ip_agg AS (
            SELECT
                src_ip,
                count(*)                                           AS pkt_count,
                count(DISTINCT dst_port)                           AS port_count,
                count(DISTINCT dt)                                 AS day_count,
                count(*) FILTER (WHERE tcp_flags = 2)              AS syn_n,
                count(*) FILTER (WHERE tcp_flags = 1)              AS fin_n,
                count(*) FILTER (WHERE tcp_flags = 0)              AS null_n,
                count(*) FILTER (WHERE tcp_flags = 41)             AS xmas_n,
                min(ts)                                            AS first_seen,
                max(ts)                                            AS last_seen,
                list(DISTINCT dst_port ORDER BY dst_port) FILTER
                    (WHERE dst_port IS NOT NULL)                    AS ports_list
            FROM packets
            WHERE proto = 6 AND {where}
            GROUP BY src_ip
            HAVING count(DISTINCT dst_port) >= {min_ports}
        )
        SELECT * FROM ip_agg
        ORDER BY port_count DESC
    """).fetchall()
    print(f"[portscans] {len(rows):,} IPs hit {min_ports}+ ports", file=sys.stderr)

    con.close()

    geo = lib.GeoLookup()
    results: list[dict] = []
    type_counts: dict[str, int] = defaultdict(int)

    for r in rows:
        ip, pkt, ports, days = r[0], r[1], r[2], r[3]
        syn_n, fin_n, null_n, xmas_n = r[4], r[5], r[6], r[7]
        first_seen, last_seen = r[8], r[9]
        ports_list = r[10] or []

        if not lib.is_real_external_ip(ip):
            continue

        total_flag = syn_n + fin_n + null_n + xmas_n
        if total_flag == 0:
            total_flag = 1
        scan_type = _classify_flags(syn_n / total_flag, fin_n / total_flag,
                                    null_n / total_flag, xmas_n / total_flag)

        if ports >= 100:
            scan_type = f"horizontal_{scan_type}"
        elif days >= 30 and ports < 20:
            scan_type = f"vertical_{scan_type}"

        type_counts[scan_type] += 1
        top_ports_str = ",".join(str(p) for p in ports_list[:20])
        flag_str = f"S:{syn_n} F:{fin_n} N:{null_n} X:{xmas_n}"

        geo_rec = geo.lookup(ip)
        results.append({
            "src_ip": ip, "scan_type": scan_type, "port_count": ports,
            "pkt_count": pkt, "day_count": days, "top_ports": top_ports_str,
            "flag_profile": flag_str, "first_seen": first_seen, "last_seen": last_seen,
            "country_iso": geo_rec.country_iso, "asn": geo_rec.asn,
            "asn_org": geo_rec.asn_org,
        })

    geo.close()
    results.sort(key=lambda r: r["port_count"], reverse=True)

    top_n = args.limit or 40
    type_summary = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)

    md = f"""## Summary

- **{len(results):,}** scanning IPs detected (hitting {min_ports}+ distinct ports)

## By scan type

"""
    md += lib.markdown_table(
        [{"scan_type": t, "ip_count": c} for t, c in type_summary],
        columns=["scan_type", "ip_count"],
    )
    md += f"\n## Top {top_n} scanners by port count\n\n"
    md += lib.markdown_table(
        [{k: v for k, v in r.items() if k != "top_ports"}
         for r in results[:top_n]],
        columns=["src_ip", "scan_type", "port_count", "pkt_count", "day_count",
                 "flag_profile", "country_iso", "asn_org"],
    )

    print(f"[portscans] {len(results):,} scanners detected", file=sys.stderr)
    return lib.Report(name="portscans", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[portscans] wrote {paths['parquet']}")
    print(f"[portscans] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

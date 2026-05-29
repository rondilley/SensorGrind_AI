#!/usr/bin/env python3
"""
slowlow - slow-and-low scan detection.

Catches reconnaissance that hides under noise floors of traditional
scan detectors.  These are sources that touch a *small* number of
ports/days at a time but persist for many distinct calendar days,
often from the same /24 or ASN, often at a regular cadence.

Heuristics:
  - daily_avg_packets <= ``--max-daily-packets`` (default 12)
  - daily_avg_ports   <= ``--max-daily-ports``   (default 3)
  - active_days       >= ``--min-active-days``   (default 14)
  - span_days         >= ``--min-span-days``     (default 60)
  - active_days / span_days <= ``--max-density`` (default 0.35) — true
    slow scanners are sparse on calendar, not consistent dailies

The output also flags subnets (/24 IPv4) where two or more distinct IPs
match these criteria — the typical signature of a distributed slow
scanner using a rented CIDR.
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from collections import defaultdict
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


RESULT_SCHEMA = pa.schema([
    ("src_ip",            pa.string()),
    ("pkt_count",         pa.uint64()),
    ("port_count",        pa.uint32()),
    ("active_days",       pa.uint16()),
    ("span_days",         pa.uint16()),
    ("density",           pa.float32()),
    ("daily_avg_packets", pa.float32()),
    ("daily_avg_ports",   pa.float32()),
    ("first_seen",        pa.timestamp("us", tz="UTC")),
    ("last_seen",         pa.timestamp("us", tz="UTC")),
    ("country_iso",       pa.string()),
    ("asn",               pa.uint32()),
    ("asn_org",           pa.string()),
    ("subnet24",          pa.string()),
    ("subnet_members",    pa.uint16()),
])


def _subnet24(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except ValueError:
        return ""


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[slowlow] aggregating per-IP daily packet stats...", file=sys.stderr)
    rows = con.execute(f"""
        WITH agg AS (
            SELECT
                src_ip,
                count(*)                       AS pkt_count,
                count(DISTINCT dst_port)       AS port_count,
                count(DISTINCT dt)             AS active_days,
                DATE_DIFF('day', min(CAST(ts AS DATE)),
                                 max(CAST(ts AS DATE))) + 1 AS span_days,
                min(ts)                        AS first_seen,
                max(ts)                        AS last_seen
            FROM packets
            WHERE {where}
            GROUP BY src_ip
            HAVING count(DISTINCT dt) >= {args.min_active_days}
               AND (DATE_DIFF('day', min(CAST(ts AS DATE)),
                                     max(CAST(ts AS DATE))) + 1)
                   >= {args.min_span_days}
        )
        SELECT * FROM agg
    """).fetchall()
    con.close()
    print(f"[slowlow] {len(rows):,} IPs passed span+active gate",
          file=sys.stderr)

    geo = lib.GeoLookup()
    by_subnet: dict[str, list[str]] = defaultdict(list)
    candidates: list[dict] = []

    for r in rows:
        ip, pkt, ports, active, span, first_seen, last_seen = r
        if not lib.is_real_external_ip(ip):
            continue
        daily_p = pkt / active if active else 0.0
        daily_pt = ports / active if active else 0.0
        density = active / span if span else 0.0
        if daily_p > args.max_daily_packets:
            continue
        if daily_pt > args.max_daily_ports:
            continue
        if density > args.max_density:
            continue
        sn = _subnet24(ip)
        by_subnet[sn].append(ip)
        g = geo.lookup(ip)
        candidates.append({
            "src_ip":            ip,
            "pkt_count":         int(pkt),
            "port_count":        int(ports),
            "active_days":       int(active),
            "span_days":         int(span),
            "density":           float(density),
            "daily_avg_packets": float(daily_p),
            "daily_avg_ports":   float(daily_pt),
            "first_seen":        first_seen,
            "last_seen":         last_seen,
            "country_iso":       g.country_iso,
            "asn":               g.asn,
            "asn_org":           g.asn_org,
            "subnet24":          sn,
            "subnet_members":    0,
        })
    geo.close()

    for c in candidates:
        c["subnet_members"] = len(by_subnet.get(c["subnet24"], []))

    candidates.sort(key=lambda x: (-x["span_days"], -x["active_days"]))

    distributed = sorted(
        ((sn, len(ips)) for sn, ips in by_subnet.items() if len(ips) >= 2),
        key=lambda x: -x[1],
    )[:30]

    md = (
        "## Summary\n\n"
        f"- **{len(candidates):,}** slow-and-low scanners detected "
        f"(daily packets <= {args.max_daily_packets}, "
        f"daily ports <= {args.max_daily_ports}, "
        f"active days >= {args.min_active_days}, "
        f"calendar span >= {args.min_span_days}d, "
        f"density <= {args.max_density:.0%}).\n"
        f"- **{len(distributed):,}** /24 subnets host 2+ slow scanners "
        "(distributed-actor signature).\n\n"
        "## Top 40 slow scanners by span\n\n"
    )
    md += lib.markdown_table(
        candidates[:40],
        columns=["src_ip", "active_days", "span_days", "density",
                 "daily_avg_packets", "daily_avg_ports",
                 "country_iso", "asn_org", "subnet24", "subnet_members"],
    )
    if distributed:
        md += "\n\n## Top distributed slow-scan /24 subnets\n\n"
        md += "| subnet | members |\n| --- | --- |\n"
        for sn, n in distributed:
            md += f"| `{sn}` | {n} |\n"

    print(f"[slowlow] {len(candidates):,} slow scanners, "
          f"{len(distributed)} distributed subnets", file=sys.stderr)
    return lib.Report(name="slowlow", rows=candidates,
                      schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    ap.add_argument("--max-daily-packets", type=float, default=12.0)
    ap.add_argument("--max-daily-ports", type=float, default=3.0)
    ap.add_argument("--min-active-days", type=int, default=14)
    ap.add_argument("--min-span-days", type=int, default=60)
    ap.add_argument("--max-density", type=float, default=0.35,
                    help="Reject IPs that are active on too high a fraction "
                         "of calendar days (they're not slow, they're "
                         "consistent low-volume).")
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[slowlow] wrote {paths['parquet']}")
    print(f"[slowlow] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

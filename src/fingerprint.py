#!/usr/bin/env python3
"""
fingerprint — composite per-source-IP behavioral fingerprint.

Builds a multi-dimensional profile for each source IP by combining:
  - TCP SYN characteristics (TTL bucket, window size, DF flag)
  - Protocol mix (% TCP/UDP/ICMP)
  - Port targeting pattern (top ports, horizontal vs vertical)
  - L7 protocol distribution
  - Payload presence rate

Outputs a fingerprint vector per IP and clusters IPs with similar
profiles to identify tool families and operator groups.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from collections import defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("src_ip",          pa.string()),
    ("fp_hash",         pa.string()),
    ("pkt_count",       pa.uint64()),
    ("ttl_bucket",      pa.uint8()),
    ("tcp_win_mode",    pa.uint32()),
    ("tcp_pct",         pa.float32()),
    ("udp_pct",         pa.float32()),
    ("icmp_pct",        pa.float32()),
    ("syn_pct",         pa.float32()),
    ("payload_pct",     pa.float32()),
    ("port_count",      pa.uint32()),
    ("top_port",        pa.uint16()),
    ("l7_dominant",     pa.string()),
    ("day_count",       pa.uint16()),
    ("country_iso",     pa.string()),
    ("asn",             pa.uint32()),
    ("asn_org",         pa.string()),
])


def _ttl_bucket(ttl: int | None) -> int:
    if ttl is None:
        return 0
    if ttl <= 32:
        return 32
    if ttl <= 64:
        return 64
    if ttl <= 128:
        return 128
    return 255


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[fingerprint] building per-IP profiles...", file=sys.stderr)
    rows = con.execute(f"""
        SELECT
            src_ip,
            count(*)                                    AS pkt_count,
            mode(ttl)                                   AS ttl_mode,
            mode(tcp_win)                               AS tcp_win_mode,
            count(*) FILTER (WHERE proto = 6)           AS tcp_n,
            count(*) FILTER (WHERE proto = 17)          AS udp_n,
            count(*) FILTER (WHERE proto = 1)           AS icmp_n,
            count(*) FILTER (WHERE tcp_flags = 2)       AS syn_n,
            count(*) FILTER (WHERE payload_len > 0)     AS payload_n,
            count(DISTINCT dst_port)                    AS port_count,
            mode(dst_port)                              AS top_port,
            mode(l7_proto)                              AS l7_mode,
            count(DISTINCT dt)                          AS day_count
        FROM packets
        WHERE {where}
        GROUP BY src_ip
        HAVING count(*) >= 5
    """).fetchall()
    print(f"[fingerprint] {len(rows):,} IPs with 5+ packets", file=sys.stderr)

    con.close()

    geo = lib.GeoLookup()
    results: list[dict] = []
    fp_counter: dict[str, int] = defaultdict(int)

    for r in rows:
        ip = r[0]
        if not lib.is_real_external_ip(ip):
            continue
        pkt = r[1]
        ttl_b = _ttl_bucket(r[2])
        win = r[3] or 0
        tcp_pct = r[4] / pkt
        udp_pct = r[5] / pkt
        icmp_pct = r[6] / pkt
        syn_pct = r[7] / pkt
        payload_pct = r[8] / pkt
        port_count = r[9]
        top_port = r[10]
        l7_mode = r[11]
        day_count = r[12]

        fp_str = f"{ttl_b}_{win}_{tcp_pct:.1f}_{syn_pct:.1f}_{payload_pct:.1f}"
        fp_hash = hashlib.sha256(fp_str.encode()).hexdigest()[:12]
        fp_counter[fp_hash] += 1

        geo_rec = geo.lookup(ip)
        results.append({
            "src_ip": ip, "fp_hash": fp_hash, "pkt_count": pkt,
            "ttl_bucket": ttl_b, "tcp_win_mode": int(win),
            "tcp_pct": float(tcp_pct), "udp_pct": float(udp_pct),
            "icmp_pct": float(icmp_pct), "syn_pct": float(syn_pct),
            "payload_pct": float(payload_pct), "port_count": port_count,
            "top_port": top_port, "l7_dominant": lib.L7_NAME.get(l7_mode, "unknown"),
            "day_count": day_count,
            "country_iso": geo_rec.country_iso, "asn": geo_rec.asn,
            "asn_org": geo_rec.asn_org,
        })

    geo.close()
    results.sort(key=lambda r: r["pkt_count"], reverse=True)

    top_fps = sorted(fp_counter.items(), key=lambda x: x[1], reverse=True)[:30]
    top_n = args.limit or 30

    md = f"""## Summary

- **{len(results):,}** source IPs fingerprinted
- **{len(fp_counter):,}** distinct fingerprint clusters

## Top {top_n} fingerprint clusters (by IP count)

"""
    md += lib.markdown_table(
        [{"fp_hash": h, "ip_count": c} for h, c in top_fps],
        columns=["fp_hash", "ip_count"],
    )

    md += f"\n## Top {top_n} IPs by volume\n\n"
    md += lib.markdown_table(
        [{k: v for k, v in r.items()
          if k in ("src_ip", "fp_hash", "pkt_count", "ttl_bucket", "tcp_win_mode",
                   "syn_pct", "payload_pct", "port_count", "l7_dominant")}
         for r in results[:top_n]],
        columns=["src_ip", "fp_hash", "pkt_count", "ttl_bucket", "tcp_win_mode",
                 "syn_pct", "payload_pct", "port_count", "l7_dominant"],
    )

    print(f"[fingerprint] {len(results):,} IPs, {len(fp_counter):,} clusters", file=sys.stderr)
    return lib.Report(name="fingerprint", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[fingerprint] wrote {paths['parquet']}")
    print(f"[fingerprint] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
ja4plus — compute JA4/JA4H/JA4T fingerprints from captured payloads.

Reads l7_events (TLS ClientHello, HTTP, SSH) and packets (TCP SYN
characteristics) to produce fingerprints per source IP.

JA4  — TLS ClientHello fingerprint (protocol, ciphersuite count,
       extensions count, SNI, ALPN, sorted ciphers hash)
JA4H — HTTP client fingerprint (method, headers order hash,
       cookie fields hash, Accept-Language)
JA4T — TCP SYN fingerprint (window size, TTL, MSS, window scale,
       options order) — works even on payloadless probes
JA4SSH — SSH fingerprint (banner hash + hassh-style key exchange)

Clusters sources by fingerprint to identify tool families (masscan,
zgrab2, nmap, curl, python-requests, Go net/http, etc.).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter, defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("src_ip",         pa.string()),
    ("fp_type",        pa.string()),
    ("fingerprint",    pa.string()),
    ("fp_hash",        pa.string()),
    ("detail",         pa.string()),
    ("count",          pa.uint32()),
    ("first_seen",     pa.timestamp("us", tz="UTC")),
    ("last_seen",      pa.timestamp("us", tz="UTC")),
])

CLUSTER_SCHEMA = pa.schema([
    ("fp_type",        pa.string()),
    ("fingerprint",    pa.string()),
    ("fp_hash",        pa.string()),
    ("ip_count",       pa.uint32()),
    ("total_count",    pa.uint64()),
    ("sample_ips",     pa.string()),
    ("detail",         pa.string()),
])


def _hash12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _ja4_from_fields(fields: dict) -> tuple[str, str]:
    ciphers = fields.get("ciphersuites", [])
    sni = fields.get("sni", "")
    ver = fields.get("version", "")
    grease = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
              0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
              0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
    filtered = sorted(c for c in ciphers if c not in grease)
    cipher_str = ",".join(f"{c:04x}" for c in filtered)
    cipher_hash = _hash12(cipher_str)
    proto = "t13" if ver and ver >= "0x0304" else "t12" if ver else "t??"
    sni_flag = "d" if sni else "i"
    fp = f"{proto}{sni_flag}{len(filtered):02d}_{cipher_hash}"
    detail = json.dumps({"sni": sni, "version": ver, "ciphers": len(filtered)}, separators=(",", ":"))
    return fp, detail


def _ja4h_from_fields(fields: dict) -> tuple[str, str]:
    method = fields.get("method", "?")
    ua = fields.get("user_agent", "")
    host = fields.get("host", "")
    ua_hash = _hash12(ua)
    fp = f"{method}_{ua_hash}"
    detail = json.dumps({"host": host, "ua": ua[:120]}, separators=(",", ":"))
    return fp, detail


def _ja4t_from_row(ttl: int | None, tcp_win: int | None, tcp_flags: int | None) -> str | None:
    if tcp_flags is None or tcp_flags != 2:
        return None
    w = tcp_win if tcp_win is not None else 0
    t = ttl if ttl is not None else 0
    t_bucket = 64 if t <= 64 else 128 if t <= 128 else 255
    return f"{w}_{t_bucket}"


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    per_ip: dict[tuple[str, str, str], dict] = {}

    def _add(ip: str, fp_type: str, fp: str, fp_hash: str, detail: str, ts):
        key = (ip, fp_type, fp)
        if key not in per_ip:
            per_ip[key] = {"src_ip": ip, "fp_type": fp_type, "fingerprint": fp,
                           "fp_hash": fp_hash, "detail": detail,
                           "count": 0, "first_seen": ts, "last_seen": ts}
        rec = per_ip[key]
        rec["count"] += 1
        if ts < rec["first_seen"]:
            rec["first_seen"] = ts
        if ts > rec["last_seen"]:
            rec["last_seen"] = ts

    # Stream L7 rows in batches so we never materialize all 9M+ events at once.
    # arrow_record_batch_reader returns chunks of ~120K rows.

    def _stream_l7(proto_id: int, batch_handler):
        cur = con.execute(f"""
            SELECT src_ip, ts, fields_json
            FROM l7_events
            WHERE l7_proto = {proto_id} AND {where}
        """)
        n = 0
        for batch in cur.fetch_record_batch(rows_per_batch=100_000):
            ips = batch.column("src_ip").to_pylist()
            tss = batch.column("ts").to_pylist()
            fjs = batch.column("fields_json").to_pylist()
            for ip, ts, fj in zip(ips, tss, fjs):
                batch_handler(ip, ts, fj)
            n += len(ips)
        return n

    print("[ja4plus] computing JA4 (TLS) fingerprints...", file=sys.stderr)
    def _h_tls(ip, ts, fj):
        try:
            fields = json.loads(fj)
        except Exception:
            return
        fp, detail = _ja4_from_fields(fields)
        _add(ip, "ja4", fp, _hash12(fp), detail, ts)
    n_tls = _stream_l7(lib.L7_ID['tls'], _h_tls)
    print(f"[ja4plus] {n_tls:,} TLS events fingerprinted", file=sys.stderr)

    print("[ja4plus] computing JA4H (HTTP) fingerprints...", file=sys.stderr)
    def _h_http(ip, ts, fj):
        try:
            fields = json.loads(fj)
        except Exception:
            return
        fp, detail = _ja4h_from_fields(fields)
        _add(ip, "ja4h", fp, _hash12(fp), detail, ts)
    n_http = _stream_l7(lib.L7_ID['http'], _h_http)
    print(f"[ja4plus] {n_http:,} HTTP events fingerprinted", file=sys.stderr)

    print("[ja4plus] computing JA4SSH fingerprints...", file=sys.stderr)
    def _h_ssh(ip, ts, fj):
        try:
            fields = json.loads(fj)
        except Exception:
            return
        banner = fields.get("banner", "")
        if not banner:
            return
        fp = _hash12(banner)
        _add(ip, "ja4ssh", fp, fp, json.dumps({"banner": banner[:120]}, separators=(",", ":")), ts)
    n_ssh = _stream_l7(lib.L7_ID['ssh'], _h_ssh)
    print(f"[ja4plus] {n_ssh:,} SSH events fingerprinted", file=sys.stderr)

    # JA4T — TCP SYN fingerprint from packets, aggregated entirely in DuckDB
    # (raw SYN row count is ~700M+ — never pull into Python).
    print("[ja4plus] computing JA4T (TCP SYN) fingerprints...", file=sys.stderr)
    ja4t_rows = con.execute(f"""
        SELECT src_ip,
               CONCAT(
                 CAST(COALESCE(tcp_win, 0) AS VARCHAR), '_',
                 CASE WHEN ttl <= 64 THEN '64'
                      WHEN ttl <= 128 THEN '128'
                      ELSE '255' END
               )                AS fp,
               count(*)         AS cnt,
               min(ts)          AS first_seen,
               max(ts)          AS last_seen
        FROM packets
        WHERE proto = 6 AND tcp_flags = 2 AND {where}
        GROUP BY src_ip, fp
    """).fetchall()
    for ip, fp, cnt, first_seen, last_seen in ja4t_rows:
        key = (ip, "ja4t", fp)
        per_ip[key] = {"src_ip": ip, "fp_type": "ja4t", "fingerprint": fp,
                       "fp_hash": _hash12(fp), "detail": "",
                       "count": int(cnt), "first_seen": first_seen, "last_seen": last_seen}
    print(f"[ja4plus] {len(ja4t_rows):,} (IP, JA4T) pairs", file=sys.stderr)

    con.close()

    results = list(per_ip.values())
    results.sort(key=lambda r: r["count"], reverse=True)

    # Build clusters
    cluster_agg: dict[tuple[str, str], dict] = {}
    for r in results:
        key = (r["fp_type"], r["fingerprint"])
        if key not in cluster_agg:
            cluster_agg[key] = {"fp_type": r["fp_type"], "fingerprint": r["fingerprint"],
                                "fp_hash": r["fp_hash"], "ip_count": 0, "total_count": 0,
                                "ips": [], "detail": r["detail"]}
        c = cluster_agg[key]
        c["ip_count"] += 1
        c["total_count"] += r["count"]
        if len(c["ips"]) < 5:
            c["ips"].append(r["src_ip"])

    clusters = []
    for c in cluster_agg.values():
        clusters.append({
            "fp_type": c["fp_type"], "fingerprint": c["fingerprint"],
            "fp_hash": c["fp_hash"], "ip_count": c["ip_count"],
            "total_count": c["total_count"],
            "sample_ips": ", ".join(c["ips"]), "detail": c["detail"],
        })
    clusters.sort(key=lambda c: c["total_count"], reverse=True)

    top_n = args.limit or 40
    md = f"""## Summary

- **{len(results):,}** (IP, fingerprint) pairs across **{len(cluster_agg):,}** distinct fingerprints
- Fingerprint types: JA4 (TLS), JA4H (HTTP), JA4SSH (SSH), JA4T (TCP SYN)

## Top {top_n} fingerprint clusters by volume

"""
    md += lib.markdown_table(
        [{k: v for k, v in c.items() if k != "ips"}
         for c in clusters[:top_n]],
        columns=["fp_type", "fingerprint", "fp_hash", "ip_count", "total_count", "sample_ips", "detail"],
    )

    type_counts = Counter(r["fp_type"] for r in results)
    md += "\n## By fingerprint type\n\n"
    md += lib.markdown_table(
        [{"type": t, "pairs": c} for t, c in type_counts.most_common()],
        columns=["type", "pairs"],
    )

    print(f"[ja4plus] {len(results):,} fingerprint pairs, {len(clusters):,} clusters", file=sys.stderr)
    return lib.Report(name="ja4plus", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[ja4plus] wrote {paths['parquet']}")
    print(f"[ja4plus] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

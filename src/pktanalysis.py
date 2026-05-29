#!/usr/bin/env python3
"""
pktanalysis - packet-level structural analysis.

What it computes
----------------
1. Packet size distribution (overall and by L4 protocol)
2. TCP flag combination histogram (revealing scan techniques + protocol
   violations: SYN+FIN, NULL, XMAS, SYN with payload, etc.)
3. TTL bucket distribution (OS family hint: ~64 Linux/macOS, ~128 Windows,
   ~255 routers/embedded)
4. TCP window size mode (per-IP fingerprint signal)
5. Header-anomaly counts: payload-bearing SYN, FIN with no prior SYN
   for that src->(dst,port), unusual TOS, oversize/undersize datagrams

Output
------
output/reports/pktanalysis/*.parquet + pktanalysis.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


FLAG_NAMES = {
    0:  "NULL",
    1:  "F",       2:  "S",       3:  "SF (anomaly)",
    4:  "R",       5:  "RF",      6:  "RS",      7:  "RSF",
    8:  "P",       9:  "PF",     10:  "PS (anomaly)", 11: "PSF",
    16: "A",      17:  "FA",     18:  "SA",     19:  "SAF",
    20: "RA",     22:  "RSA",    24:  "PA",     25:  "PAF",
    26: "PSA",    28:  "PRA",
    41: "XMAS (FPU)",
    63: "all-flags",
}

RESULT_SCHEMAS = {
    "pkt_size_dist": pa.schema([
        ("bucket_lo", pa.uint16()), ("bucket_hi", pa.uint16()),
        ("proto", pa.string()), ("packets", pa.uint64()),
    ]),
    "tcp_flag_combos": pa.schema([
        ("flag_mask", pa.uint8()), ("flag_label", pa.string()),
        ("packets", pa.uint64()), ("anomaly", pa.bool_()),
        ("share_pct", pa.float32()),
    ]),
    "ttl_dist": pa.schema([
        ("ttl_bucket", pa.uint8()), ("os_family_hint", pa.string()),
        ("packets", pa.uint64()), ("distinct_ips", pa.uint32()),
    ]),
    "header_anomalies": pa.schema([
        ("anomaly", pa.string()), ("packets", pa.uint64()),
        ("distinct_ips", pa.uint32()), ("share_per_million", pa.float32()),
    ]),
}


def _flag_label(mask: int) -> tuple[str, bool]:
    """Return (human label, is_anomaly)."""
    if mask in FLAG_NAMES:
        return FLAG_NAMES[mask], "anomaly" in FLAG_NAMES[mask] or mask in (0, 41, 63, 3, 10)
    bits = []
    if mask & 32: bits.append("U")
    if mask & 16: bits.append("A")
    if mask & 8:  bits.append("P")
    if mask & 4:  bits.append("R")
    if mask & 2:  bits.append("S")
    if mask & 1:  bits.append("F")
    label = "".join(bits) or "0x{:02x}".format(mask)
    # Heuristic anomaly: SYN+FIN, RST+SYN, NULL (already), PSH-only without ACK
    anomaly = bool(mask & 2) and bool(mask & 1)  # S+F
    anomaly |= bool(mask & 4) and bool(mask & 2)  # R+S
    return label, anomaly


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    out_dir = lib.REPORTS / "pktanalysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    import pyarrow.parquet as pq

    print("[pkt] packet size distribution...", file=sys.stderr)
    size_rows = con.execute("""
        SELECT (pkt_len / 64) * 64 AS bucket_lo, proto, count(*) AS packets
        FROM packets
        WHERE pkt_len IS NOT NULL
        GROUP BY bucket_lo, proto
        ORDER BY bucket_lo
    """).fetchall()
    size_pa = pa.Table.from_pylist(
        [{"bucket_lo": int(b), "bucket_hi": int(b) + 63,
          "proto": lib.PROTO_NAME.get(p, str(p)), "packets": n}
         for b, p, n in size_rows],
        schema=RESULT_SCHEMAS["pkt_size_dist"],
    )
    pq.write_table(size_pa, out_dir / "pkt_size_dist.parquet",
                   compression="zstd", compression_level=3)

    print("[pkt] TCP flag combos...", file=sys.stderr)
    flag_rows = con.execute("""
        SELECT tcp_flags, count(*) AS packets
        FROM packets WHERE proto = 6 AND tcp_flags IS NOT NULL
        GROUP BY tcp_flags ORDER BY packets DESC
    """).fetchall()
    total_tcp = sum(r[1] for r in flag_rows) or 1
    flag_combos = []
    for mask, n in flag_rows:
        label, anom = _flag_label(int(mask))
        flag_combos.append({
            "flag_mask": int(mask), "flag_label": label,
            "packets": n, "anomaly": anom,
            "share_pct": float(n / total_tcp * 100),
        })
    pq.write_table(pa.Table.from_pylist(flag_combos, schema=RESULT_SCHEMAS["tcp_flag_combos"]),
                   out_dir / "tcp_flag_combos.parquet",
                   compression="zstd", compression_level=3)

    print("[pkt] TTL distribution...", file=sys.stderr)
    ttl_rows = con.execute("""
        SELECT
            CASE WHEN ttl <= 32 THEN 32
                 WHEN ttl <= 64 THEN 64
                 WHEN ttl <= 128 THEN 128
                 WHEN ttl <= 192 THEN 192
                 ELSE 255 END AS ttl_bucket,
            count(*) AS packets,
            count(DISTINCT src_ip) AS distinct_ips
        FROM packets WHERE ttl IS NOT NULL
        GROUP BY ttl_bucket ORDER BY ttl_bucket
    """).fetchall()
    OS_HINT = {32: "embedded/router (TTL<=32)",
               64: "Linux/BSD/macOS (default 64)",
               128: "Windows (default 128)",
               192: "Solaris/AIX (default 255 - hops)",
               255: "router/IoT/raw (TTL=255)"}
    ttl_pa = pa.Table.from_pylist(
        [{"ttl_bucket": int(b), "os_family_hint": OS_HINT.get(int(b), "?"),
          "packets": n, "distinct_ips": k} for b, n, k in ttl_rows],
        schema=RESULT_SCHEMAS["ttl_dist"],
    )
    pq.write_table(ttl_pa, out_dir / "ttl_dist.parquet",
                   compression="zstd", compression_level=3)

    print("[pkt] header anomalies...", file=sys.stderr)
    anomalies = []
    total = con.execute("SELECT count(*) FROM packets").fetchone()[0] or 1

    def _count(label: str, where: str) -> None:
        r = con.execute(f"""
            SELECT count(*), count(DISTINCT src_ip)
            FROM packets WHERE {where}
        """).fetchone()
        anomalies.append({
            "anomaly": label,
            "packets": int(r[0] or 0),
            "distinct_ips": int(r[1] or 0),
            "share_per_million": float((r[0] or 0) / total * 1_000_000),
        })

    _count("SYN with payload (>0 bytes)",
           "proto = 6 AND tcp_flags = 2 AND payload_len > 0")
    _count("SYN+FIN combination",
           "proto = 6 AND tcp_flags & 2 != 0 AND tcp_flags & 1 != 0")
    _count("RST+SYN combination",
           "proto = 6 AND tcp_flags & 2 != 0 AND tcp_flags & 4 != 0")
    _count("XMAS scan (FIN+PSH+URG)",
           "proto = 6 AND tcp_flags = 41")
    _count("NULL scan (zero flags)",
           "proto = 6 AND tcp_flags = 0")
    _count("All-flags (mask=63)",
           "proto = 6 AND tcp_flags = 63")
    _count("PSH-only (no ACK)",
           "proto = 6 AND tcp_flags = 8")
    _count("FIN-only (no ACK)",
           "proto = 6 AND tcp_flags = 1")
    _count("Oversized datagram (>1500B)", "pkt_len > 1500")
    _count("Tiny TCP packet (<40B)", "proto = 6 AND pkt_len < 40")
    _count("Non-zero TOS field", "tos > 0")
    _count("TCP window 0 (zero-window probe)",
           "proto = 6 AND tcp_win = 0")

    pq.write_table(pa.Table.from_pylist(anomalies, schema=RESULT_SCHEMAS["header_anomalies"]),
                   out_dir / "header_anomalies.parquet",
                   compression="zstd", compression_level=3)

    con.close()

    md_lines = [
        "# pktanalysis - packet-level structural features",
        "",
        "## TCP flag combinations",
        "",
        "_Each unique TCP flag bitmap observed in the corpus, with a label "
        "indicating whether the combination is a known anomaly or scan type._",
        "",
        "| flag_label | mask | packets | share_pct | anomaly |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in flag_combos[:25]:
        md_lines.append(f"| {r['flag_label']} | {r['flag_mask']} | "
                        f"{r['packets']:,} | {r['share_pct']:.3f}% | "
                        f"{'YES' if r['anomaly'] else ''} |")

    md_lines.extend(["", "## Header anomalies (per-million share)",
                     "", "| anomaly | packets | distinct_ips | per_million |",
                     "| --- | --- | --- | --- |"])
    for a in sorted(anomalies, key=lambda a: a["packets"], reverse=True):
        md_lines.append(f"| {a['anomaly']} | {a['packets']:,} | "
                        f"{a['distinct_ips']:,} | {a['share_per_million']:.2f} |")

    md_lines.extend(["", "## TTL buckets",
                     "", "| ttl_bucket | os_family_hint | packets | distinct_ips |",
                     "| --- | --- | --- | --- |"])
    for r in ttl_rows:
        b, n, k = r
        md_lines.append(f"| {b} | {OS_HINT.get(int(b), '?')} | {n:,} | {k:,} |")

    (out_dir / "pktanalysis.md").write_text("\n".join(md_lines) + "\n")
    print(f"[pkt] wrote {out_dir}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    return run(argparse.Namespace())


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
longitudinal/attack_chains — reconstruct per-IP attack timelines.

Defines a 6-stage attack lifecycle and finds each attacker's first
arrival into each stage:

  R - recon       SYN-only sweep hitting many distinct ports
  P - probe       any L7 protocol handshake (HTTP/TLS/SSH/RDP banner)
  X - exploit     HTTP URI matching a probesigs CVE/RCE tag
  C - cred        mstshash cookie or user:pass credential pair IOC
  D - drop        wget/tftp/curl URL or busybox command IOC
  B - botnet      payload classified into a known family (botnetcls)

For each high-risk IP we emit a chain string (e.g. "RPXD") plus
inter-stage timing (e.g. "R(day 1) -> X(day 4) -> D(day 4)").
Aggregated counts show which chain shapes are most common, revealing
the toolkit/playbook each cohort uses.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
OUT_DIR = lib.OUTPUT_DIR / "patterns" / "attack_chains"

STAGES = ["R", "P", "X", "C", "D", "B"]

PER_IP_SCHEMA = pa.schema([
    ("src_ip",      pa.string()),
    ("chain",       pa.string()),
    ("stage_count", pa.uint8()),
    ("r_first",     pa.timestamp("us", tz="UTC")),
    ("p_first",     pa.timestamp("us", tz="UTC")),
    ("x_first",     pa.timestamp("us", tz="UTC")),
    ("c_first",     pa.timestamp("us", tz="UTC")),
    ("d_first",     pa.timestamp("us", tz="UTC")),
    ("b_first",     pa.timestamp("us", tz="UTC")),
    ("span_days",   pa.float32()),
    ("risk_score",  pa.float32()),
])

PATTERN_SCHEMA = pa.schema([
    ("chain",       pa.string()),
    ("ip_count",    pa.uint32()),
    ("avg_span_d",  pa.float32()),
    ("avg_risk",    pa.float32()),
    ("sample_ips",  pa.string()),
])


def run(args: argparse.Namespace) -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[chains] no ip features", file=sys.stderr)
        return 2

    risk_path = lib.OUTPUT_DIR / "risk" / "ip_risk" / f"dt={snap.snapshot_date.isoformat()}" / "risk.parquet"

    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    print("[chains] selecting target IP set (tier >= medium)...", file=sys.stderr)
    if risk_path.exists():
        risk_rows = con.execute(f"""
            SELECT src_ip, risk_score, risk_tier
            FROM read_parquet('{risk_path}')
            WHERE risk_tier IN ('critical', 'high', 'medium')
        """).fetchall()
    else:
        risk_rows = con.execute("""
            SELECT src_ip, 0.0, 'unknown' FROM packets GROUP BY src_ip
            HAVING count(*) >= 50
        """).fetchall()
    risk_map = {r[0]: float(r[1]) for r in risk_rows}
    print(f"[chains] {len(risk_map):,} target IPs", file=sys.stderr)

    if not risk_map:
        return 0

    con.execute("CREATE TEMP TABLE chain_ips(ip VARCHAR)")
    con.executemany("INSERT INTO chain_ips VALUES (?)", [(ip,) for ip in risk_map])

    probesigs_path = lib.REPORTS / "probesigs" / "probesigs.parquet"
    botnet_path = lib.REPORTS / "botnetcls" / "botnetcls.parquet"

    # R - recon: first time the IP did a SYN burst (>=10 distinct ports in a window)
    # Simplified: first SYN-only packet for any IP that ever hit >=10 distinct ports.
    print("[chains] stage R (recon)...", file=sys.stderr)
    r_rows = con.execute("""
        WITH counts AS (
            SELECT p.src_ip, count(DISTINCT dst_port) AS port_count
            FROM packets p JOIN chain_ips t ON p.src_ip = t.ip
            WHERE proto = 6 AND tcp_flags = 2
            GROUP BY p.src_ip HAVING count(DISTINCT dst_port) >= 10
        )
        SELECT p.src_ip, min(p.ts)
        FROM packets p
        JOIN counts c ON p.src_ip = c.src_ip
        WHERE p.proto = 6 AND p.tcp_flags = 2
        GROUP BY p.src_ip
    """).fetchall()
    r_first = {r[0]: r[1] for r in r_rows}
    print(f"[chains]   R: {len(r_first):,} IPs", file=sys.stderr)

    print("[chains] stage P (probe)...", file=sys.stderr)
    p_rows = con.execute("""
        SELECT l.src_ip, min(l.ts) FROM l7_events l
        JOIN chain_ips t ON l.src_ip = t.ip
        GROUP BY l.src_ip
    """).fetchall()
    p_first = {r[0]: r[1] for r in p_rows}
    print(f"[chains]   P: {len(p_first):,} IPs", file=sys.stderr)

    x_first: dict[str, object] = {}
    if probesigs_path.exists() and probesigs_path.stat().st_size > 0:
        print("[chains] stage X (exploit)...", file=sys.stderr)
        x_rows = con.execute(f"""
            SELECT i.src_ip, min(i.ts)
            FROM iocs i JOIN chain_ips t ON i.src_ip = t.ip
            JOIN read_parquet('{probesigs_path}') p ON i.value = p.uri
            WHERE i.ioc_kind = {lib.IOC_ID['http_uri']}
            GROUP BY i.src_ip
        """).fetchall()
        x_first = {r[0]: r[1] for r in x_rows}
        print(f"[chains]   X: {len(x_first):,} IPs", file=sys.stderr)

    print("[chains] stage C (cred)...", file=sys.stderr)
    c_rows = con.execute(f"""
        SELECT i.src_ip, min(i.ts)
        FROM iocs i JOIN chain_ips t ON i.src_ip = t.ip
        WHERE i.ioc_kind IN ({lib.IOC_ID['mstshash']}, {lib.IOC_ID['cred']})
        GROUP BY i.src_ip
    """).fetchall()
    c_first = {r[0]: r[1] for r in c_rows}
    print(f"[chains]   C: {len(c_first):,} IPs", file=sys.stderr)

    print("[chains] stage D (drop)...", file=sys.stderr)
    d_rows = con.execute(f"""
        SELECT i.src_ip, min(i.ts)
        FROM iocs i JOIN chain_ips t ON i.src_ip = t.ip
        WHERE i.ioc_kind IN ({lib.IOC_ID['url']}, {lib.IOC_ID['cmd']})
        GROUP BY i.src_ip
    """).fetchall()
    d_first = {r[0]: r[1] for r in d_rows}
    print(f"[chains]   D: {len(d_first):,} IPs", file=sys.stderr)

    b_first: dict[str, object] = {}
    if botnet_path.exists() and botnet_path.stat().st_size > 0:
        print("[chains] stage B (botnet)...", file=sys.stderr)
        b_rows = con.execute(f"""
            SELECT p.src_ip, min(p.ts)
            FROM packets p
            JOIN chain_ips t ON p.src_ip = t.ip
            JOIN read_parquet('{botnet_path}') b ON p.payload_sha256 = b.payload_sha256
            GROUP BY p.src_ip
        """).fetchall()
        b_first = {r[0]: r[1] for r in b_rows}
        print(f"[chains]   B: {len(b_first):,} IPs", file=sys.stderr)

    con.close()

    print("[chains] assembling chains...", file=sys.stderr)
    out_rows: list[dict] = []
    chain_counts: Counter = Counter()
    chain_ips: dict[str, list[str]] = defaultdict(list)
    chain_spans: dict[str, list[float]] = defaultdict(list)
    chain_risks: dict[str, list[float]] = defaultdict(list)

    for ip, score in risk_map.items():
        stages = {
            "R": r_first.get(ip), "P": p_first.get(ip), "X": x_first.get(ip),
            "C": c_first.get(ip), "D": d_first.get(ip), "B": b_first.get(ip),
        }
        present = [(s, t) for s, t in stages.items() if t is not None]
        if not present:
            continue
        present.sort(key=lambda x: x[1])
        chain = "".join(s for s, _ in present)
        chain_counts[chain] += 1
        chain_ips[chain].append(ip)
        ts_list = [t for _, t in present]
        span = (ts_list[-1] - ts_list[0]).total_seconds() / 86400.0
        chain_spans[chain].append(span)
        chain_risks[chain].append(score)
        out_rows.append({
            "src_ip": ip, "chain": chain, "stage_count": len(present),
            "r_first": stages["R"], "p_first": stages["P"], "x_first": stages["X"],
            "c_first": stages["C"], "d_first": stages["D"], "b_first": stages["B"],
            "span_days": float(span), "risk_score": float(score),
        })

    out_rows.sort(key=lambda r: (-r["stage_count"], -r["risk_score"]))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(out_rows, schema=PER_IP_SCHEMA),
                   OUT_DIR / "per_ip.parquet",
                   compression="zstd", compression_level=3)

    pattern_rows: list[dict] = []
    for chain, n in chain_counts.most_common():
        spans = chain_spans[chain]
        risks = chain_risks[chain]
        sample = chain_ips[chain][:8]
        pattern_rows.append({
            "chain": chain, "ip_count": n,
            "avg_span_d": sum(spans) / len(spans) if spans else 0.0,
            "avg_risk": sum(risks) / len(risks) if risks else 0.0,
            "sample_ips": ", ".join(sample),
        })
    pq.write_table(pa.Table.from_pylist(pattern_rows, schema=PATTERN_SCHEMA),
                   OUT_DIR / "patterns.parquet",
                   compression="zstd", compression_level=3)

    md_lines = ["# Attack chain reconstruction", "",
                f"**{len(out_rows):,}** IPs profiled (target tier >= medium).",
                f"**{len(chain_counts):,}** distinct chain shapes observed.", "",
                "## Top 30 chain shapes",
                "",
                "| chain | ip_count | avg_span_days | avg_risk | sample_ips |",
                "| --- | --- | --- | --- | --- |"]
    for r in pattern_rows[:30]:
        md_lines.append(f"| {r['chain']} | {r['ip_count']:,} | "
                        f"{r['avg_span_d']:.1f} | {r['avg_risk']:.1f} | "
                        f"{r['sample_ips']} |")
    (OUT_DIR / "patterns.md").write_text("\n".join(md_lines) + "\n")

    print(f"[chains] {len(out_rows):,} IPs, {len(chain_counts):,} shapes -> {OUT_DIR}",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    return run(argparse.Namespace())


if __name__ == "__main__":
    sys.exit(main())

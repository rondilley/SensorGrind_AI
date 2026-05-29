#!/usr/bin/env python3
"""
risk/risk_dossier — generate per-IP markdown dossier for high-risk IPs.

Batched implementation: instead of running per-IP queries against the
1.1B-row packets table (N queries x full scan), we filter packets/iocs
once by the chosen IP set via a temp table, then GROUP BY src_ip in
DuckDB to get all needed aggregates for all IPs at once.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
DOSSIER_DIR = lib.OUTPUT_DIR / "risk" / "dossiers"

TIER_ORDER = ["critical", "high", "medium", "low", "info"]


def _bar_chart_text(values: list[int], width: int = 60) -> str:
    if not values:
        return ""
    mx = max(values) or 1
    bucket = max(1, len(values) // width)
    out = []
    for i in range(0, len(values), bucket):
        chunk = values[i:i+bucket]
        avg = sum(chunk) / len(chunk)
        h = int(round(avg / mx * 8))
        out.append("=" * h if h else ".")
    return " ".join(out)


def run(args: argparse.Namespace) -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[dossier] no features", file=sys.stderr)
        return 2

    risk_path = lib.OUTPUT_DIR / "risk" / "ip_risk" / f"dt={snap.snapshot_date.isoformat()}" / "risk.parquet"
    if not risk_path.exists():
        print(f"[dossier] no risk file at {risk_path}", file=sys.stderr)
        return 2

    min_tier_idx = TIER_ORDER.index(args.min_tier)

    con = lib.duck(memory_limit="12GB")
    lib.register_views(con)

    print(f"[dossier] selecting tier >= {args.min_tier}...", file=sys.stderr)
    risk_rows = con.execute(f"""
        SELECT src_ip, risk_score, risk_tier, ml_score, rationale,
               persistence, breadth, exploit_signal, botnet_signal,
               infra_signal, anomaly_signal, benign_offset
        FROM read_parquet('{risk_path}')
        ORDER BY risk_score DESC
    """).fetchall()
    risk_rows = [r for r in risk_rows if TIER_ORDER.index(r[2]) <= min_tier_idx]
    if args.limit:
        risk_rows = risk_rows[: args.limit]
    print(f"[dossier] {len(risk_rows):,} IPs to profile", file=sys.stderr)
    if not risk_rows:
        return 0

    target_ips = [r[0] for r in risk_rows]

    # Materialize the target IP list once.
    con.execute("CREATE TEMP TABLE target_ips(ip VARCHAR)")
    con.executemany("INSERT INTO target_ips VALUES (?)", [(ip,) for ip in target_ips])

    feats_path = sf.snapshot_dir(snap) / "part-0000.parquet"
    feats_rows = con.execute(f"""
        SELECT f.* FROM read_parquet('{feats_path}') f
        JOIN target_ips t ON f.src_ip = t.ip
    """).fetchall()
    feats_cols = [c[0] for c in con.execute(f"DESCRIBE SELECT * FROM read_parquet('{feats_path}')").fetchall()]
    feats = {r[0]: dict(zip(feats_cols, r)) for r in feats_rows}

    print("[dossier] batch query: IOCs per target IP...", file=sys.stderr)
    ioc_rows = con.execute("""
        WITH ranked AS (
            SELECT i.src_ip, i.ioc_kind, i.value,
                   count(*) AS hits,
                   row_number() OVER (PARTITION BY i.src_ip ORDER BY count(*) DESC) AS rn
            FROM iocs i JOIN target_ips t ON i.src_ip = t.ip
            GROUP BY i.src_ip, i.ioc_kind, i.value
        )
        SELECT src_ip, ioc_kind, value, hits FROM ranked WHERE rn <= 20
    """).fetchall()
    iocs_by_ip: dict[str, list[tuple]] = defaultdict(list)
    for ip, kind, val, hits in ioc_rows:
        iocs_by_ip[ip].append((kind, val, hits))

    print("[dossier] batch query: daily activity per target IP...", file=sys.stderr)
    daily_rows = con.execute("""
        SELECT p.src_ip, CAST(p.ts AS DATE) AS d, count(*) AS c
        FROM packets p JOIN target_ips t ON p.src_ip = t.ip
        GROUP BY p.src_ip, d
        ORDER BY p.src_ip, d
    """).fetchall()
    daily_by_ip: dict[str, list[tuple]] = defaultdict(list)
    for ip, d, c in daily_rows:
        daily_by_ip[ip].append((d, int(c)))

    print("[dossier] batch query: top ports per target IP...", file=sys.stderr)
    port_rows = con.execute("""
        WITH ranked AS (
            SELECT p.src_ip, p.dst_port, count(*) AS c,
                   row_number() OVER (PARTITION BY p.src_ip ORDER BY count(*) DESC) AS rn
            FROM packets p JOIN target_ips t ON p.src_ip = t.ip
            GROUP BY p.src_ip, p.dst_port
        )
        SELECT src_ip, dst_port, c FROM ranked WHERE rn <= 10
    """).fetchall()
    ports_by_ip: dict[str, list[tuple]] = defaultdict(list)
    for ip, port, c in port_rows:
        ports_by_ip[ip].append((port, c))

    con.close()

    DOSSIER_DIR.mkdir(parents=True, exist_ok=True)
    index_lines = [f"# Risk dossiers ({snap.snapshot_date}) - tier >= {args.min_tier}",
                   "", f"{len(risk_rows):,} IPs profiled.", "",
                   "| rank | src_ip | tier | score | rationale | dossier |",
                   "| --- | --- | --- | --- | --- | --- |"]

    for rank, rr in enumerate(risk_rows, start=1):
        ip = rr[0]
        feat_dict = feats.get(ip)
        if not feat_dict:
            continue

        slug = ip.replace(".", "_")
        path = DOSSIER_DIR / f"{slug}.md"
        lines = [
            f"# {ip} - risk {rr[1]:.1f} ({rr[2]})",
            "",
            f"_rationale: {rr[4]}_",
            "",
            "## Risk components",
            "",
            "| component | value |",
            "| --- | --- |",
            f"| ML threat score | {rr[3]:.3f} |",
            f"| persistence | {rr[5]:.1f} |",
            f"| breadth | {rr[6]:.1f} |",
            f"| exploit signal | {rr[7]:.1f} |",
            f"| botnet signal | {rr[8]:.1f} |",
            f"| infrastructure | {rr[9]:.1f} |",
            f"| anomaly | {rr[10]:.1f} |",
            f"| benign offset | {rr[11]:.1f} |",
            "",
            "## Identity",
            "",
            f"- ASN: **{feat_dict.get('asn')}** {feat_dict.get('asn_org', '')}",
            f"- Country: **{feat_dict.get('country_iso')}**",
            f"- First seen: {feat_dict.get('first_seen')}",
            f"- Last seen: {feat_dict.get('last_seen')}",
            f"- Days active: **{feat_dict.get('day_count')}** over {feat_dict.get('span_days', 0):.1f}d",
            "",
            "## Behavior",
            "",
            f"- {feat_dict.get('pkt_count'):,} packets, {feat_dict.get('byte_count', 0):,} bytes",
            f"- {feat_dict.get('port_count')} distinct dst ports",
            f"- TCP={feat_dict.get('pct_tcp', 0):.0%} UDP={feat_dict.get('pct_udp', 0):.0%} ICMP={feat_dict.get('pct_icmp', 0):.0%}",
            f"- SYN-only {feat_dict.get('pct_syn_only', 0):.0%}, payload-bearing {feat_dict.get('pct_with_payload', 0):.0%}",
            f"- Dominant L7: **{feat_dict.get('l7_dominant')}** ({feat_dict.get('l7_event_count')} events)",
            f"- TTL mode {feat_dict.get('ttl_mode')}, TCP win mode {feat_dict.get('tcp_win_mode')}",
            "",
            "## Top destination ports",
            "",
            "| port | hits |",
            "| --- | --- |",
        ]
        for port, c in ports_by_ip.get(ip, []):
            lines.append(f"| {port} | {c:,} |")

        ip_iocs = iocs_by_ip.get(ip, [])
        if ip_iocs:
            lines.extend(["", "## IOCs observed (top 20)",
                          "", "| kind | value | hits |", "| --- | --- | --- |"])
            for kind, val, hits in ip_iocs:
                kname = lib.IOC_NAME.get(kind, str(kind))
                v = str(val)[:120].replace("|", "\\|")
                lines.append(f"| {kname} | {v} | {hits} |")

        ip_daily = daily_by_ip.get(ip, [])
        if ip_daily:
            spark_vals = [c for _, c in ip_daily]
            lines.extend(["", "## Daily activity",
                          "", "```",
                          _bar_chart_text(spark_vals),
                          f"({len(spark_vals)} active days, peak {max(spark_vals):,} pkts/day)",
                          "```"])

        path.write_text("\n".join(lines) + "\n")
        index_lines.append(f"| {rank} | {ip} | {rr[2]} | {rr[1]:.1f} | "
                           f"{rr[4][:80]} | [{slug}.md]({slug}.md) |")

    (DOSSIER_DIR / "INDEX.md").write_text("\n".join(index_lines) + "\n")
    print(f"[dossier] wrote {len(risk_rows):,} dossiers + INDEX.md to {DOSSIER_DIR}",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-tier", default="high", choices=TIER_ORDER)
    ap.add_argument("--limit", type=int, default=100, help="Max dossiers to write")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

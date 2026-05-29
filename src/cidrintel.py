#!/usr/bin/env python3
"""
cidrintel - CIDR-block threat profile (/24 and /16).

Goal: find compromised subnets and bulletproof-hosting blocks where
many IPs in close address proximity behave hostilely.  Useful for
defenders deciding between IP-block (precise but slow), /24-block
(catches whole compromised blocks but risks collateral) and ASN-block.

For each /24 and /16 we report:
  - count of IPs we observed
  - count of medium+ threat IPs
  - threat_density
  - dominant ASN(s) and country
  - dominant botnet family if any
  - "block_score" - density-weighted IP count, lets you sort the worst
    blocks first
  - block_recommend - per-block defender action
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from collections import Counter
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
OUT_DIR = lib.REPORTS / "cidrintel"

RESULT_SCHEMA = pa.schema([
    ("cidr",            pa.string()),
    ("prefix_len",      pa.uint8()),
    ("ip_count",        pa.uint32()),
    ("threat_ip_count", pa.uint32()),
    ("threat_density",  pa.float32()),
    ("top_asn",         pa.uint32()),
    ("top_asn_org",     pa.string()),
    ("top_country",     pa.string()),
    ("top_botnet_fam",  pa.string()),
    ("top_dst_port",    pa.uint16()),
    ("avg_risk",        pa.float32()),
    ("block_score",     pa.float32()),
    ("block_recommend", pa.string()),
])


def _grade_block(density: float, n_threat: int, prefix_len: int) -> str:
    if prefix_len == 24:
        if density >= 0.80 and n_threat >= 10:
            return "block_/24 high-confidence whole-subnet block"
        if density >= 0.50 and n_threat >= 5:
            return "block_/24 with monitoring; collateral risk if mixed-use"
        if n_threat >= 3:
            return "per-IP block; subnet is mixed-use"
        return "per-IP only"
    # /16
    if density >= 0.50 and n_threat >= 100:
        return "block_/16 - this /16 is dominated by hostile activity"
    if density >= 0.30 and n_threat >= 50:
        return "monitor_/16 - subnet-level patterns developing; flag for review"
    if n_threat >= 20:
        return "block worst /24s within this /16"
    return "no /16-level action; /24 or per-IP"


def _supernet(ip: str, prefix: int) -> str | None:
    try:
        n = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(n)
    except Exception:
        return None


def run(args: argparse.Namespace) -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[cidrintel] no ip features", file=sys.stderr)
        return 2
    feat_path = sf.snapshot_dir(snap) / "part-0000.parquet"
    risk_path = (lib.OUTPUT_DIR / "risk" / "ip_risk"
                 / f"dt={snap.snapshot_date.isoformat()}" / "risk.parquet")
    if not risk_path.exists():
        print("[cidrintel] no risk file", file=sys.stderr)
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    print("[cidrintel] joining features + risk + packets aggregates...",
          file=sys.stderr)
    rows = con.execute(f"""
        SELECT f.src_ip, f.asn, f.asn_org, f.country_iso, f.top_port,
               f.botnet_family, f.pkt_count,
               r.risk_score, r.risk_tier
        FROM read_parquet('{feat_path}') f
        JOIN read_parquet('{risk_path}') r ON f.src_ip = r.src_ip
        WHERE f.src_ip IS NOT NULL
    """).fetchall()
    print(f"[cidrintel] {len(rows):,} per-IP rows", file=sys.stderr)
    con.close()

    bucket24: dict[str, dict] = {}
    bucket16: dict[str, dict] = {}

    for ip, asn, asn_org, cc, top_port, family, pkt_count, risk, tier in rows:
        try:
            n24 = _supernet(ip, 24)
            n16 = _supernet(ip, 16)
        except Exception:
            continue
        for cidr, bucket, plen in ((n24, bucket24, 24), (n16, bucket16, 16)):
            if not cidr:
                continue
            b = bucket.setdefault(cidr, {
                "ips": 0, "threat_ips": 0, "asn_counts": Counter(),
                "country_counts": Counter(), "fam_counts": Counter(),
                "port_counts": Counter(), "asn_org_seen": {},
                "risk_sum": 0.0,
            })
            b["ips"] += 1
            if tier in ("critical", "high", "medium"):
                b["threat_ips"] += 1
            if asn:
                b["asn_counts"][int(asn)] += 1
                b["asn_org_seen"][int(asn)] = asn_org or ""
            if cc:
                b["country_counts"][cc] += 1
            if family:
                b["fam_counts"][family] += 1
            if top_port is not None:
                b["port_counts"][int(top_port)] += 1
            b["risk_sum"] += float(risk or 0)

    out_rows: list[dict] = []
    for plen, bucket in ((24, bucket24), (16, bucket16)):
        for cidr, b in bucket.items():
            n = b["ips"]
            t = b["threat_ips"]
            if n < args.min_ips:
                continue
            density = t / n if n else 0.0
            top_asn = b["asn_counts"].most_common(1)
            top_asn_n, top_asn_org = (0, "")
            if top_asn:
                top_asn_n = top_asn[0][0]
                top_asn_org = b["asn_org_seen"].get(top_asn_n, "")
            top_cc = b["country_counts"].most_common(1)
            top_fam = b["fam_counts"].most_common(1)
            top_port = b["port_counts"].most_common(1)
            avg_risk = b["risk_sum"] / n
            block_score = float(t) * (density ** 0.7)
            out_rows.append({
                "cidr": cidr, "prefix_len": plen,
                "ip_count": n, "threat_ip_count": t,
                "threat_density": float(density),
                "top_asn": int(top_asn_n) if top_asn_n else 0,
                "top_asn_org": top_asn_org[:64],
                "top_country": top_cc[0][0] if top_cc else "",
                "top_botnet_fam": top_fam[0][0] if top_fam else "",
                "top_dst_port": int(top_port[0][0]) if top_port else 0,
                "avg_risk": float(avg_risk),
                "block_score": float(block_score),
                "block_recommend": _grade_block(density, t, plen),
            })

    out_rows.sort(key=lambda r: (-r["block_score"], -r["threat_density"]))
    pq.write_table(pa.Table.from_pylist(out_rows, schema=RESULT_SCHEMA),
                   OUT_DIR / "cidrintel.parquet",
                   compression="zstd", compression_level=3)

    md = [
        "# cidrintel - CIDR-block threat profile (/24 and /16)", "",
        "_For each CIDR with >=" + str(args.min_ips) + " observed IPs we "
        "compute threat density, dominant ASN/country/family, and a "
        "block_score that ranks subnets by 'how hostile is it and "
        "how big is the impact?'.  Highest scores at top are the most "
        "actionable subnet-level blocks._", "",
        "## Grade meaning",
        "",
        "| pattern | when defenders use it |",
        "| --- | --- |",
        "| `block_/24` | Confidence high enough to block the whole subnet |",
        "| `block_/16` | Subnet large but mostly hostile - extreme cases only |",
        "| `monitor_/16` | Heightened scrutiny but not a hard block |",
        "| `block worst /24s within this /16` | /16 too coarse; act at /24 |",
        "| `per-IP block` | Subnet is mixed use; precise per-IP blocks only |",
        "",
        "## Top 50 /24 blocks ranked by block_score",
        "",
        "| cidr | ips | threats | density | top_asn_org | cc | fam | port | rec |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    top24 = [r for r in out_rows if r["prefix_len"] == 24][:50]
    for r in top24:
        md.append(
            f"| {r['cidr']} | {r['ip_count']:,} | {r['threat_ip_count']:,} | "
            f"{r['threat_density']:.0%} | {r['top_asn_org'][:28]} | "
            f"{r['top_country']} | {r['top_botnet_fam']} | "
            f"{r['top_dst_port']} | {r['block_recommend'][:50]} |"
        )

    md.extend(["", "## Top 30 /16 blocks ranked by block_score",
               "",
               "| cidr | ips | threats | density | top_asn_org | cc | fam | port | rec |",
               "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"])
    top16 = [r for r in out_rows if r["prefix_len"] == 16][:30]
    for r in top16:
        md.append(
            f"| {r['cidr']} | {r['ip_count']:,} | {r['threat_ip_count']:,} | "
            f"{r['threat_density']:.0%} | {r['top_asn_org'][:28]} | "
            f"{r['top_country']} | {r['top_botnet_fam']} | "
            f"{r['top_dst_port']} | {r['block_recommend'][:50]} |"
        )
    (OUT_DIR / "cidrintel.md").write_text("\n".join(md) + "\n")
    print(f"[cidrintel] wrote {OUT_DIR} "
          f"({len(top24)} /24s, {len(top16)} /16s)", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-ips", type=int, default=5,
                    help="Minimum observed IPs per CIDR to include "
                         "(default 5)")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

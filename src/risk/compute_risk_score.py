#!/usr/bin/env python3
"""
risk/compute_risk_score — composite per-IP risk score + tier assignment.

Combines the ML threat_classifier probability with hand-tuned
heuristic boosts (persistence, infrastructure quality, targeting
breadth, exploit-probe count, botnet-family confirmation) into a
0-100 composite risk score with explanatory components.

Output: data/risk/ip_risk/dt=YYYY-MM-DD/risk.parquet
        + tier counts written to risk_summary.md
"""
from __future__ import annotations

import argparse
import datetime as _dt
import math
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
OUT_BASE = lib.OUTPUT_DIR / "risk" / "ip_risk"

SCHEMA = pa.schema([
    ("src_ip",          pa.string()),
    ("risk_score",      pa.float32()),
    ("risk_tier",       pa.string()),
    ("ml_score",        pa.float32()),
    ("persistence",     pa.float32()),
    ("breadth",         pa.float32()),
    ("exploit_signal",  pa.float32()),
    ("botnet_signal",   pa.float32()),
    ("infra_signal",    pa.float32()),
    ("anomaly_signal",  pa.float32()),
    ("benign_offset",   pa.float32()),
    ("neuro_signal",    pa.float32()),
    ("rationale",       pa.string()),
])


def tier(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


# Heuristic ASN reputation buckets (very coarse — refine over time).
BULLETPROOF_KEYWORDS = ("media land", "skynet", "tamatiya", "iptransit",
                        "mevspace", "layer7 networks", "iproyal",
                        "net-surf", "ip volume", "pfcloud", "latitude.sh")
CLOUD_KEYWORDS = ("amazon", "google", "microsoft", "azure", "digitalocean",
                  "vultr", "linode", "ovh", "hetzner", "alibaba",
                  "tencent", "constant company")
RESIDENTIAL_KEYWORDS = ("comcast", "cox", "verizon", "att", "spectrum",
                        "telecom", "broadband", "china mobile", "china unicom")


# Neuromorphic term (ARCHITECTURE §9.1 Phase 4), capped so that it can move
# a source by part of one tier only.  neuro_change / neuro_reg are -log10
# exceedance rates of the source's best day; log10(days) removes the gain
# that a source gets from many days of tests.
NEURO_FLAG = 4.0
# Known scanners inside a published scanner CIDR (benignfilter evidence
# "cidr:") take a small reduction (operator decision 2026-10-25); scanners
# found only by user agent or ASN keep their behavior score.
SCANNER_CIDR_OFFSET = -10.0
# Arrival cap 0 (operator decision 2026-10-25): an stl_z alarm minute is a
# property of all traffic, so it gave points to every source active in it.
# Restore only with a per-source share of the excess packets.
NEURO_LIF_CAP, NEURO_ARRIVAL_CAP, NEURO_CAP = 6.0, 0.0, 8.0
# HDC choreography term: hdc_proto / hdc_drift passed their matched rff_*
# twins on rotating_actor (test and development sets, 2026-10-27).  Same
# excess rule as the LIF term; the shared NEURO_CAP still limits the total.
NEURO_HDC_CAP = 4.0


def neuro_score(r: dict) -> tuple[float, str]:
    days = max(1, r.get("neuro_days") or 0)
    best = max(r.get("neuro_change") or 0.0, r.get("neuro_reg") or 0.0)
    excess = best - NEURO_FLAG - math.log10(days)
    lif_term = min(NEURO_LIF_CAP, 2.0 * max(0.0, excess))
    arr = r.get("neuro_arrival_min") or 0
    arr_term = min(NEURO_ARRIVAL_CAP, math.log2(1 + arr)) if arr else 0.0
    hp, hd = r.get("neuro_hdc_proto") or 0.0, r.get("neuro_hdc_drift") or 0.0
    h_excess = (max(hp, hd) - NEURO_FLAG
                - math.log10(max(1, r.get("neuro_hdc_days") or 0)))
    hdc_term = min(NEURO_HDC_CAP, 2.0 * max(0.0, h_excess))
    label = []
    if lif_term > 0:
        kind = ("rate-shift" if (r.get("neuro_change") or 0) >=
                (r.get("neuro_reg") or 0) else "metronome")
        label.append(f"lif-{kind}={best:.1f}")
    if hdc_term > 0:
        label.append(f"hdc-{'proto' if hp >= hd else 'drift'}="
                     f"{max(hp, hd):.1f}")
    if arr_term > 0:
        label.append(f"arrival-alarm={arr}min")
    return (min(NEURO_CAP, lif_term + hdc_term + arr_term),
            ", ".join(label))


def infra_score(asn_org: str) -> tuple[float, str]:
    s = (asn_org or "").lower()
    if any(k in s for k in BULLETPROOF_KEYWORDS):
        return 20.0, "bulletproof"
    if any(k in s for k in CLOUD_KEYWORDS):
        return 8.0, "cloud"
    if any(k in s for k in RESIDENTIAL_KEYWORDS):
        return 4.0, "residential"
    return 6.0, "unknown"


def run() -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[risk] no ip features available", file=sys.stderr)
        return 2

    # Load threat scores if available.
    scores_dir = lib.OUTPUT_DIR / "risk" / "threat_scores"
    score_map: dict[str, float] = {}
    if scores_dir.exists():
        latest = sorted(scores_dir.glob("scores_*.parquet"))
        if latest:
            con = lib.duck()
            rows = con.execute(f"SELECT src_ip, threat_score FROM read_parquet('{latest[-1]}')").fetchall()
            score_map = {r[0]: float(r[1]) for r in rows}
            con.close()
            print(f"[risk] loaded ML scores for {len(score_map):,} IPs from {latest[-1].name}",
                  file=sys.stderr)

    cidr_scanners: set[str] = set()
    bf = lib.REPORTS / "benignfilter" / "benignfilter.parquet"
    if bf.exists():
        con = lib.duck()
        cidr_scanners = {r[0] for r in con.execute(
            f"SELECT src_ip FROM read_parquet('{bf}') "
            "WHERE evidence LIKE '%cidr:%'").fetchall()}
        con.close()
        print(f"[risk] {len(cidr_scanners):,} IPs in published scanner CIDRs",
              file=sys.stderr)

    table = sf.load_snapshot(snap)
    print(f"[risk] scoring {table.num_rows:,} IPs...", file=sys.stderr)

    out_rows: list[dict] = []
    tier_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for r in table.to_pylist():
        ip = r["src_ip"]
        ml = score_map.get(ip, 0.0)

        # Persistence: log scale over distinct days; cap at 20 points.
        days = r["day_count"] or 0
        persistence = min(20.0, 3.0 * (days ** 0.5))

        # Breadth: how many distinct ports + payloads they touch.
        port_count = r["port_count"] or 0
        breadth = min(15.0,
                      4.0 * (port_count ** 0.4) +
                      0.5 * min(r["distinct_payloads"] or 0, 30))

        # Exploit signal: HTTP IOCs (URIs) hitting many distinct paths.
        d_uri = r["distinct_uris"] or 0
        exploit_signal = min(15.0, 1.5 * (d_uri ** 0.5))

        # Botnet signal: known family classification adds 15 points.
        botnet_signal = 15.0 if (r["botnet_family"] or "") else 0.0

        # Infrastructure quality (bulletproof / cloud / residential).
        infra_signal, infra_label = infra_score(r["asn_org"])

        # Anomaly signal: ECOD score, normalized.
        anom = float(r["anomaly_score"] or 0)
        anomaly_signal = min(10.0, anom / 5.0)

        # Benign offset (operator decision 2026-10-25): a small reduction
        # for an IP in a published scanner CIDR only.  Other known scanners
        # score by their behavior; benign_org stays in the rationale.
        in_cidr = ip in cidr_scanners
        benign_offset = SCANNER_CIDR_OFFSET if in_cidr else 0.0

        neuro_signal, neuro_label = neuro_score(r)

        composite = (35.0 * ml +
                     persistence + breadth + exploit_signal +
                     botnet_signal + infra_signal + anomaly_signal +
                     neuro_signal + benign_offset)
        composite = max(0.0, min(100.0, composite))

        t = tier(composite)
        tier_counts[t] += 1

        rationale_parts = []
        if ml > 0.5:
            rationale_parts.append(f"ML={ml:.2f}")
        if r["botnet_family"]:
            rationale_parts.append(f"botnet={r['botnet_family']}")
        if r["scan_type"]:
            rationale_parts.append(r["scan_type"])
        if d_uri >= 5:
            rationale_parts.append(f"uris={d_uri}")
        if days >= 100:
            rationale_parts.append(f"persist={days}d")
        if r["benign_org"]:
            rationale_parts.append(f"known-scanner={r['benign_org']}"
                                   + (" (published CIDR)" if in_cidr else ""))
        if neuro_label:
            rationale_parts.append(neuro_label)
        rationale_parts.append(f"infra={infra_label}")

        out_rows.append({
            "src_ip": ip, "risk_score": float(composite), "risk_tier": t,
            "ml_score": ml,
            "persistence": persistence, "breadth": breadth,
            "exploit_signal": exploit_signal, "botnet_signal": botnet_signal,
            "infra_signal": infra_signal, "anomaly_signal": anomaly_signal,
            "benign_offset": benign_offset, "neuro_signal": neuro_signal,
            "rationale": ", ".join(rationale_parts),
        })

    out_rows.sort(key=lambda r: r["risk_score"], reverse=True)

    out_dir = OUT_BASE / f"dt={snap.snapshot_date.isoformat()}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "risk.parquet"
    pq.write_table(pa.Table.from_pylist(out_rows, schema=SCHEMA),
                   out_path, compression="zstd", compression_level=3)

    md_lines = [f"# Risk summary {snap.snapshot_date}",
                "",
                f"Total IPs scored: **{len(out_rows):,}**",
                "",
                "## Tier breakdown",
                "",
                "| tier | ips |",
                "| --- | --- |"]
    for t in ("critical", "high", "medium", "low", "info"):
        md_lines.append(f"| {t} | {tier_counts[t]:,} |")
    md_lines.extend(["", "## Top 25 IPs by composite risk", "",
                     "| src_ip | tier | score | rationale |",
                     "| --- | --- | --- | --- |"])
    for r in out_rows[:25]:
        md_lines.append(f"| {r['src_ip']} | {r['risk_tier']} | "
                        f"{r['risk_score']:.1f} | {r['rationale']} |")
    (out_dir / "summary.md").write_text("\n".join(md_lines) + "\n")

    print(f"[risk] wrote {out_path}", file=sys.stderr)
    print(f"[risk] tiers: " + " ".join(f"{k}={v:,}" for k, v in tier_counts.items()),
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()
    return run()


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
longitudinal/survival_analysis — IP lifetime distributions by cohort.

For each IP we have first_seen / last_seen from the feature snapshot,
so lifetime = last_seen - first_seen in days. IPs with last_seen
within 7 days of the corpus end are treated as right-censored
(still active).

Buckets IPs by cohort and computes empirical survival curves
(Kaplan-Meier-equivalent for these mostly-uncensored data) to show
how persistence varies across:
  - country
  - infrastructure class (cloud / bulletproof / residential)
  - actor cluster (HDBSCAN)
  - botnet family

Output: survival statistics + percentile lifetimes per cohort.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
OUT_DIR = lib.OUTPUT_DIR / "patterns" / "survival"

BULLETPROOF = ("media land", "skynet", "tamatiya", "iptransit", "mevspace",
               "layer7 networks", "iproyal", "net-surf", "ip volume",
               "pfcloud", "latitude.sh")
CLOUD = ("amazon", "google", "microsoft", "azure", "digitalocean", "vultr",
         "linode", "ovh", "hetzner", "alibaba", "tencent", "constant company")
RESIDENTIAL = ("comcast", "cox", "verizon", "att", "spectrum", "telecom",
               "broadband", "china mobile", "china unicom")


def infra_class(asn_org: str) -> str:
    s = (asn_org or "").lower()
    if any(k in s for k in BULLETPROOF): return "bulletproof"
    if any(k in s for k in CLOUD): return "cloud"
    if any(k in s for k in RESIDENTIAL): return "residential"
    return "unknown"


SCHEMA = pa.schema([
    ("cohort_kind", pa.string()),
    ("cohort",      pa.string()),
    ("ip_count",    pa.uint32()),
    ("median_d",    pa.float32()),
    ("p25_d",       pa.float32()),
    ("p75_d",       pa.float32()),
    ("p90_d",       pa.float32()),
    ("active_pct",  pa.float32()),
])


def percentiles(arr: np.ndarray) -> dict:
    if arr.size == 0:
        return {"p25": 0, "p50": 0, "p75": 0, "p90": 0}
    return {
        "p25": float(np.percentile(arr, 25)),
        "p50": float(np.median(arr)),
        "p75": float(np.percentile(arr, 75)),
        "p90": float(np.percentile(arr, 90)),
    }


def run(args: argparse.Namespace) -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[survival] no features", file=sys.stderr)
        return 2

    con = lib.duck()
    feat_path = sf.snapshot_dir(snap) / "part-0000.parquet"
    rows = con.execute(f"""
        SELECT src_ip, country_iso, asn_org, botnet_family,
               first_seen, last_seen
        FROM read_parquet('{feat_path}')
    """).fetchall()

    assign_path = lib.OUTPUT_DIR / "patterns" / "actor_clusters" / "assignments.parquet"
    cluster_map: dict[str, int] = {}
    if assign_path.exists():
        a_rows = con.execute(f"SELECT src_ip, cluster_id FROM read_parquet('{assign_path}')").fetchall()
        cluster_map = {r[0]: int(r[1]) for r in a_rows}

    max_ts = con.execute(f"SELECT max(last_seen) FROM read_parquet('{feat_path}')").fetchone()[0]
    con.close()
    if max_ts is None:
        print("[survival] no timestamps", file=sys.stderr)
        return 2
    print(f"[survival] corpus end ~ {max_ts}", file=sys.stderr)

    cohorts: dict[tuple[str, str], list[tuple[float, bool]]] = defaultdict(list)

    for ip, cc, asn_org, fam, first, last in rows:
        if not first or not last:
            continue
        lifetime = (last - first).total_seconds() / 86400.0
        days_to_end = (max_ts - last).total_seconds() / 86400.0
        active = days_to_end <= 7
        if cc:
            cohorts[("country", cc)].append((lifetime, active))
        cohorts[("infra", infra_class(asn_org))].append((lifetime, active))
        if fam:
            cohorts[("botnet_family", fam)].append((lifetime, active))
        cid = cluster_map.get(ip)
        if cid is not None and cid >= 0:
            cohorts[("actor_cluster", str(cid))].append((lifetime, active))

    out_rows: list[dict] = []
    for (kind, name), data in cohorts.items():
        if len(data) < args.min_size:
            continue
        lifetimes = np.array([d[0] for d in data], dtype=np.float64)
        active = sum(1 for d in data if d[1]) / len(data)
        p = percentiles(lifetimes)
        out_rows.append({
            "cohort_kind": kind, "cohort": name,
            "ip_count": len(data),
            "median_d": float(p["p50"]), "p25_d": float(p["p25"]),
            "p75_d": float(p["p75"]), "p90_d": float(p["p90"]),
            "active_pct": float(active),
        })

    out_rows.sort(key=lambda r: (r["cohort_kind"], -r["ip_count"]))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(out_rows, schema=SCHEMA),
                   OUT_DIR / "cohorts.parquet",
                   compression="zstd", compression_level=3)

    md_lines = ["# Survival / persistence analysis", "",
                f"Lifetime = (last_seen - first_seen) in days, "
                f"per IP. 'active_pct' = fraction still active in "
                f"last 7 days (right-censored).", "",
                f"Min cohort size: **{args.min_size}**", ""]
    by_kind: dict[str, list] = defaultdict(list)
    for r in out_rows:
        by_kind[r["cohort_kind"]].append(r)
    for kind, rs in by_kind.items():
        md_lines.append(f"## {kind} cohorts")
        md_lines.append("")
        md_lines.append("| cohort | ips | median_d | p25_d | p75_d | p90_d | active_pct |")
        md_lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for r in rs[:30]:
            md_lines.append(f"| {r['cohort']} | {r['ip_count']:,} | "
                            f"{r['median_d']:.1f} | {r['p25_d']:.1f} | "
                            f"{r['p75_d']:.1f} | {r['p90_d']:.1f} | "
                            f"{r['active_pct']:.0%} |")
        md_lines.append("")
    (OUT_DIR / "survival.md").write_text("\n".join(md_lines) + "\n")
    print(f"[survival] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-size", type=int, default=20)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

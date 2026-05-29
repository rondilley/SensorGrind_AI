#!/usr/bin/env python3
"""
longitudinal/infra_rotation — track actor migration across ASNs over time.

For each behavioral cluster (from actor_clusterer) we compute the
per-week distribution over ASNs. Clusters whose dominant ASN shifts
significantly between adjacent weeks are flagged as 'rotating' -
the operator moved hosting providers, but the cluster's TTL/window/
port-pattern fingerprint stayed the same.

Output: rotation events with (cluster, from_asn, to_asn, week, IPs).
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
ASSIGN_PATH = lib.OUTPUT_DIR / "patterns" / "actor_clusters" / "assignments.parquet"
OUT_DIR = lib.OUTPUT_DIR / "patterns" / "infra_rotation"

ROTATION_SCHEMA = pa.schema([
    ("cluster_id",   pa.int32()),
    ("week",         pa.string()),
    ("prev_asn",     pa.uint32()),
    ("prev_asn_org", pa.string()),
    ("prev_share",   pa.float32()),
    ("next_asn",     pa.uint32()),
    ("next_asn_org", pa.string()),
    ("next_share",   pa.float32()),
    ("ip_count",     pa.uint32()),
])


def run(args: argparse.Namespace) -> int:
    if not ASSIGN_PATH.exists():
        print("[rotation] no actor cluster assignments - run train_actor_clusterer first",
              file=sys.stderr)
        return 2

    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    feat_path = sf.snapshot_dir(snap) / "part-0000.parquet"

    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    print("[rotation] joining cluster assignments with weekly activity...", file=sys.stderr)
    rows = con.execute(f"""
        WITH cluster_ips AS (
            SELECT src_ip, cluster_id
            FROM read_parquet('{ASSIGN_PATH}')
            WHERE cluster_id >= 0
        ),
        ip_geo AS (
            SELECT src_ip, asn, asn_org FROM read_parquet('{feat_path}')
        ),
        weekly AS (
            SELECT c.cluster_id,
                   date_trunc('week', p.ts)::DATE AS week,
                   g.asn, g.asn_org,
                   count(DISTINCT p.src_ip) AS ips,
                   count(*) AS pkts
            FROM packets p
            JOIN cluster_ips c ON p.src_ip = c.src_ip
            JOIN ip_geo g ON p.src_ip = g.src_ip
            GROUP BY c.cluster_id, week, g.asn, g.asn_org
        )
        SELECT cluster_id, week, asn, asn_org, ips, pkts FROM weekly
        ORDER BY cluster_id, week, pkts DESC
    """).fetchall()
    con.close()
    print(f"[rotation] {len(rows):,} (cluster, week, asn) rows", file=sys.stderr)

    # Build per-cluster per-week dominant-ASN sequence.
    by_cluster_week: dict[tuple[int, str], dict[int, dict]] = defaultdict(dict)
    for cid, wk, asn, asn_org, ips, pkts in rows:
        key = (int(cid), str(wk))
        by_cluster_week[key][int(asn or 0)] = {
            "asn_org": asn_org or "", "ips": int(ips), "pkts": int(pkts),
        }

    # For each cluster, walk weeks chronologically and detect dominant-ASN changes.
    cluster_weeks: dict[int, list[str]] = defaultdict(list)
    for (cid, wk) in by_cluster_week:
        cluster_weeks[cid].append(wk)
    for cid in cluster_weeks:
        cluster_weeks[cid].sort()

    events: list[dict] = []
    for cid, weeks in cluster_weeks.items():
        prev_dom = None
        prev_share = 0.0
        for wk in weeks:
            asns = by_cluster_week[(cid, wk)]
            total_pkts = sum(v["pkts"] for v in asns.values()) or 1
            dom_asn, dom_v = max(asns.items(), key=lambda x: x[1]["pkts"])
            dom_share = dom_v["pkts"] / total_pkts
            if prev_dom is not None and dom_asn != prev_dom:
                events.append({
                    "cluster_id": cid, "week": wk,
                    "prev_asn": prev_dom,
                    "prev_asn_org": by_cluster_week.get((cid, weeks[weeks.index(wk)-1]), {})
                                     .get(prev_dom, {}).get("asn_org", ""),
                    "prev_share": float(prev_share),
                    "next_asn": dom_asn,
                    "next_asn_org": dom_v["asn_org"],
                    "next_share": float(dom_share),
                    "ip_count": int(dom_v["ips"]),
                })
            prev_dom = dom_asn
            prev_share = dom_share

    events.sort(key=lambda e: e["ip_count"], reverse=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(events, schema=ROTATION_SCHEMA),
                   OUT_DIR / "rotations.parquet",
                   compression="zstd", compression_level=3)

    md_lines = ["# Infrastructure rotation", "",
                f"**{len(events):,}** rotation events detected across "
                f"{len(cluster_weeks):,} actor clusters.",
                "",
                "## Top 40 rotations by IP count",
                "",
                "| cluster | week | prev_asn_org | next_asn_org | ips |",
                "| --- | --- | --- | --- | --- |"]
    for e in events[:40]:
        md_lines.append(f"| {e['cluster_id']} | {e['week']} | "
                        f"{e['prev_asn_org'][:40]} | {e['next_asn_org'][:40]} | "
                        f"{e['ip_count']:,} |")
    (OUT_DIR / "rotations.md").write_text("\n".join(md_lines) + "\n")
    print(f"[rotation] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    return run(argparse.Namespace())


if __name__ == "__main__":
    sys.exit(main())

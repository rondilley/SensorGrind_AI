#!/usr/bin/env python3
"""
models/train_actor_clusterer — HDBSCAN clustering on per-IP feature vectors.

Each non-noise cluster is a likely "operator group": a set of IPs that
behave near-identically (same port targeting, protocol mix, TTL/win
fingerprint, payload patterns). Cross-checks against benignfilter/
campaign output to label clusters as benign-tool / actor / unknown.

Persists the trained HDBSCAN model + per-IP cluster assignments.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib
from sg import models as sm

FEATURE_VERSION = 1
OUT_DIR = lib.OUTPUT_DIR / "patterns" / "actor_clusters"

NUMERIC_FEATURES = [
    "pkt_count", "byte_count", "day_count", "span_days", "pkts_per_active_day",
    "pct_tcp", "pct_udp", "pct_icmp", "pct_syn_only",
    "ttl_mode", "tcp_win_mode", "port_count", "port_diversity",
    "pct_with_payload", "distinct_payloads", "avg_payload_len",
    "l7_event_count", "l7_distinct_protos",
    "ioc_count", "distinct_uas", "distinct_uris",
    "anomaly_score", "burstiness_cv",
]
LOG_FEATURES = {"pkt_count", "byte_count", "pkts_per_active_day",
                "port_count", "distinct_payloads", "l7_event_count",
                "ioc_count", "distinct_uris", "distinct_uas"}

ASSIGN_SCHEMA = pa.schema([
    ("src_ip",      pa.string()),
    ("cluster_id",  pa.int32()),
    ("probability", pa.float32()),
])

SUMMARY_SCHEMA = pa.schema([
    ("cluster_id",      pa.int32()),
    ("size",            pa.uint32()),
    # Multi-AI methodology review: surface HDBSCAN's per-cluster
    # persistence (stability) score so consumers can tell a tight
    # operator group apart from a flimsy density bump.
    ("persistence",     pa.float32()),
    ("stable",          pa.bool_()),
    ("top_country",     pa.string()),
    ("top_asn_org",     pa.string()),
    ("avg_port_count",  pa.float32()),
    ("avg_pkt_count",   pa.float32()),
    ("dominant_l7",     pa.string()),
    ("benign_fraction", pa.float32()),
    ("botnet_fraction", pa.float32()),
    ("sample_ips",      pa.string()),
])


def extract_X(table: pa.Table) -> np.ndarray:
    cols = [table.column(c).to_numpy(zero_copy_only=False).astype(np.float64)
            for c in NUMERIC_FEATURES]
    X = np.column_stack(cols)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    for i, name in enumerate(NUMERIC_FEATURES):
        if name in LOG_FEATURES:
            X[:, i] = np.log1p(np.maximum(X[:, i], 0))
    # Robust z-score (median/MAD) to stop wild-tail features dominating.
    med = np.median(X, axis=0)
    mad = np.median(np.abs(X - med), axis=0) + 1e-6
    return (X - med) / (1.4826 * mad)


def run(args: argparse.Namespace) -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[actors] no features", file=sys.stderr)
        return 2

    table = sf.load_snapshot(snap)
    # Subsample to top-N IPs by pkt_count to keep HDBSCAN feasible.
    pkts = table.column("pkt_count").to_numpy(zero_copy_only=False)
    if args.max_ips > 0 and len(pkts) > args.max_ips:
        idx = np.argsort(pkts)[-args.max_ips:]
        idx.sort()
        table = table.take(idx)
        print(f"[actors] sampled top {len(idx):,} IPs by pkt_count", file=sys.stderr)

    print("[actors] extracting and scaling features...", file=sys.stderr)
    X = extract_X(table)

    print(f"[actors] running HDBSCAN on {X.shape[0]:,} IPs x {X.shape[1]} features...",
          file=sys.stderr)
    import hdbscan
    # gen_min_span_tree=True is required to compute the relative_validity_
    # (DBCV-style) global score after fitting. Multi-AI methodology review
    # flagged that without stability metrics we can't tell a real cluster
    # from a noise lump.
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=args.min_cluster_size,
        min_samples=args.min_samples,
        cluster_selection_epsilon=0.0,
        core_dist_n_jobs=-1,
        prediction_data=False,
        gen_min_span_tree=True,
    )
    labels = clusterer.fit_predict(X)
    probs = clusterer.probabilities_
    persistence = getattr(clusterer, "cluster_persistence_", None)
    try:
        rel_validity = float(clusterer.relative_validity_)
    except Exception:
        rel_validity = float("nan")
    n_clusters = int(labels.max() + 1)
    n_noise = int((labels == -1).sum())
    if persistence is not None and len(persistence):
        stable_mask = persistence >= args.min_persistence
        n_stable = int(stable_mask.sum())
    else:
        stable_mask = np.ones(max(n_clusters, 1), dtype=bool)
        n_stable = n_clusters
    print(f"[actors] HDBSCAN found {n_clusters:,} clusters "
          f"({n_stable:,} stable >= {args.min_persistence}) + "
          f"{n_noise:,} noise; DBCV~{rel_validity:.3f}",
          file=sys.stderr)

    info = sm.ModelInfo(
        name="actor_clusterer", version=sm.next_version("actor_clusterer"),
        model_type="hdbscan.HDBSCAN",
        feature_set=f"ip:v{FEATURE_VERSION}",
        training_rows=int(X.shape[0]),
        training_range=("", ""),
        trained_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        metrics={"n_clusters": n_clusters, "n_noise": n_noise,
                 "n_stable_clusters": n_stable,
                 "min_cluster_size": args.min_cluster_size,
                 "min_samples": args.min_samples,
                 "min_persistence": args.min_persistence,
                 "relative_validity_dbcv": rel_validity,
                 "mean_persistence": (float(np.mean(persistence))
                                      if persistence is not None
                                      and len(persistence) else 0.0)},
    )
    sm.save_model("actor_clusterer", clusterer, info)
    print(f"[actors] saved model v{info.version}", file=sys.stderr)

    rows = table.to_pylist()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    assign_rows = [{"src_ip": rows[i]["src_ip"],
                    "cluster_id": int(labels[i]),
                    "probability": float(probs[i])}
                   for i in range(len(rows))]
    pq.write_table(pa.Table.from_pylist(assign_rows, schema=ASSIGN_SCHEMA),
                   OUT_DIR / "assignments.parquet",
                   compression="zstd", compression_level=3)

    # Summarize clusters
    print("[actors] summarizing clusters...", file=sys.stderr)
    by_cluster: dict[int, list] = {}
    for i, lab in enumerate(labels):
        if lab == -1:
            continue
        by_cluster.setdefault(int(lab), []).append(i)

    summaries: list[dict] = []
    for cid, idxs in by_cluster.items():
        sub = [rows[i] for i in idxs]
        countries = Counter(r["country_iso"] for r in sub if r["country_iso"])
        asns = Counter(r["asn_org"] for r in sub if r["asn_org"])
        l7s = Counter(r["l7_dominant"] for r in sub)
        benign = sum(1 for r in sub if r["benign_org"])
        botnet = sum(1 for r in sub if r["botnet_family"])
        pers = (float(persistence[cid])
                if persistence is not None and cid < len(persistence)
                else 0.0)
        summaries.append({
            "cluster_id": cid, "size": len(idxs),
            "persistence": pers,
            "stable": pers >= args.min_persistence,
            "top_country": countries.most_common(1)[0][0] if countries else "",
            "top_asn_org": asns.most_common(1)[0][0] if asns else "",
            "avg_port_count": float(np.mean([r["port_count"] for r in sub])),
            "avg_pkt_count": float(np.mean([r["pkt_count"] for r in sub])),
            "dominant_l7": l7s.most_common(1)[0][0] if l7s else "",
            "benign_fraction": benign / len(idxs),
            "botnet_fraction": botnet / len(idxs),
            "sample_ips": ", ".join(r["src_ip"] for r in sub[:8]),
        })
    summaries.sort(key=lambda r: r["size"], reverse=True)
    pq.write_table(pa.Table.from_pylist(summaries, schema=SUMMARY_SCHEMA),
                   OUT_DIR / "summary.parquet",
                   compression="zstd", compression_level=3)

    md_lines = ["# Actor cluster discovery (HDBSCAN)", "",
                f"**{n_clusters:,}** clusters discovered "
                f"({n_stable:,} stable, persistence >= {args.min_persistence}), "
                f"**{n_noise:,}** noise points",
                f"(min_cluster_size={args.min_cluster_size}, "
                f"min_samples={args.min_samples}, "
                f"DBCV~{rel_validity:.3f}).",
                "",
                "_Persistence is the HDBSCAN per-cluster stability score: "
                "how long the cluster survived as you scan the density "
                "threshold. Stable=true means persistence >= the gate. "
                "Treat unstable clusters as suggestive only — they may be "
                "noise lumps that happened to clear min_cluster_size._",
                "",
                "## Top 40 clusters by size",
                "",
                "| cid | size | persist | stable | country | asn_org | avg_ports | dom_l7 | benign% | botnet% | sample_ips |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in summaries[:40]:
        md_lines.append(
            f"| {r['cluster_id']} | {r['size']:,} | "
            f"{r['persistence']:.3f} | {'yes' if r['stable'] else 'no'} | "
            f"{r['top_country']} | {r['top_asn_org'][:30]} | "
            f"{r['avg_port_count']:.0f} | {r['dominant_l7']} | "
            f"{r['benign_fraction']:.0%} | {r['botnet_fraction']:.0%} | "
            f"{r['sample_ips']} |"
        )
    (OUT_DIR / "summary.md").write_text("\n".join(md_lines) + "\n")
    print(f"[actors] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-ips", type=int, default=100_000)
    ap.add_argument("--min-cluster-size", type=int, default=30)
    ap.add_argument("--min-samples", type=int, default=5)
    ap.add_argument("--min-persistence", type=float, default=0.10,
                    help="Cluster persistence (stability) gate. Clusters "
                         "below this are kept in output but flagged as "
                         "unstable. Default 0.10 follows McInnes 2017.")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

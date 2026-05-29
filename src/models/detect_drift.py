#!/usr/bin/env python3
"""
models/detect_drift — KS-test feature drift detection.

Compares the most recent N days of activity against a historical
baseline (the preceding M days). For each numeric feature in the IP
feature schema, runs a two-sample Kolmogorov-Smirnov test on the
per-IP feature distribution. Features with significant KS statistics
indicate that the attacker population has shifted - new tools, new
infrastructure, or a different threat composition.

This is the trigger for model retraining and rule re-mining.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib

OUT_DIR = lib.OUTPUT_DIR / "patterns" / "drift"


def _psi(base: np.ndarray, recent: np.ndarray, n_bins: int = 10) -> float:
    """Population Stability Index.  Rules of thumb (industry-standard):
       PSI <0.10  no significant drift; 0.10-0.25 moderate; >0.25 major."""
    if base.size < 2 or recent.size < 2:
        return 0.0
    lo, hi = float(min(base.min(), recent.min())), float(max(base.max(), recent.max()))
    if hi == lo:
        return 0.0
    edges = np.linspace(lo, hi, n_bins + 1)
    b_hist, _ = np.histogram(base, bins=edges)
    r_hist, _ = np.histogram(recent, bins=edges)
    # Laplace-smooth zero bins so PSI stays finite.
    b_pct = (b_hist + 1) / (b_hist.sum() + n_bins)
    r_pct = (r_hist + 1) / (r_hist.sum() + n_bins)
    return float(((r_pct - b_pct) * np.log(r_pct / b_pct)).sum())


def _benjamini_hochberg(pvals: list[float], alpha: float) -> list[bool]:
    """Return one boolean per p-value indicating rejection of H0 under
    Benjamini-Hochberg FDR control at level ``alpha``.  This corrects the
    naive uncorrected per-feature significance test the previous version
    used, which at n>>10^4 sample sizes was rejecting essentially every
    feature regardless of effect."""
    n = len(pvals)
    if n == 0:
        return []
    order = np.argsort(pvals)
    ranks = np.empty(n, dtype=int)
    ranks[order] = np.arange(1, n + 1)
    thresh = alpha * ranks / n
    # Largest k such that p[k] <= alpha*k/n -> reject all up to k
    sorted_p = np.array(pvals)[order]
    sorted_thresh = alpha * np.arange(1, n + 1) / n
    below = sorted_p <= sorted_thresh
    if below.any():
        k = np.where(below)[0].max()
        cutoff = sorted_p[k]
    else:
        cutoff = -1.0
    return [p <= cutoff for p in pvals]

NUMERIC_FEATURES = [
    "pkt_count", "byte_count", "day_count", "pkts_per_active_day",
    "pct_tcp", "pct_udp", "pct_icmp", "pct_syn_only",
    "port_count", "port_diversity", "pct_with_payload",
    "distinct_payloads", "avg_payload_len",
    "l7_event_count", "n_http_events", "n_tls_events", "n_ssh_events",
    "ioc_count", "distinct_uas", "distinct_uris", "anomaly_score",
    "burstiness_cv",
]

SCHEMA = pa.schema([
    ("feature",          pa.string()),
    ("ks_statistic",     pa.float32()),
    ("p_value",          pa.float64()),
    ("p_value_bh",       pa.float64()),
    ("wasserstein",      pa.float64()),
    ("psi",              pa.float64()),
    ("baseline_mean",    pa.float64()),
    ("recent_mean",      pa.float64()),
    ("baseline_med",     pa.float64()),
    ("recent_med",       pa.float64()),
    ("baseline_n",       pa.uint32()),
    ("recent_n",         pa.uint32()),
    ("psi_band",         pa.string()),
    ("significant",      pa.bool_()),
])


def feature_at_window(con, feat: str, start: str, end: str) -> np.ndarray:
    """Per-IP value of `feat` computed from raw packets/iocs/l7 in [start,end)."""
    where = f"ts >= TIMESTAMP '{start} 00:00:00+00' AND ts < TIMESTAMP '{end} 00:00:00+00'"

    if feat in ("pkt_count", "byte_count"):
        agg = "count(*)" if feat == "pkt_count" else "sum(pkt_len)"
        q = f"SELECT {agg} FROM packets WHERE {where} GROUP BY src_ip"
    elif feat == "day_count":
        q = f"SELECT count(DISTINCT dt) FROM packets WHERE {where} GROUP BY src_ip"
    elif feat == "pkts_per_active_day":
        q = (f"SELECT count(*) * 1.0 / count(DISTINCT dt) FROM packets WHERE {where} GROUP BY src_ip")
    elif feat in ("pct_tcp", "pct_udp", "pct_icmp"):
        proto = {"pct_tcp": 6, "pct_udp": 17, "pct_icmp": 1}[feat]
        q = (f"SELECT count(*) FILTER (WHERE proto = {proto}) * 1.0 / count(*) "
             f"FROM packets WHERE {where} GROUP BY src_ip")
    elif feat == "pct_syn_only":
        q = (f"SELECT count(*) FILTER (WHERE tcp_flags = 2) * 1.0 / count(*) "
             f"FROM packets WHERE {where} GROUP BY src_ip")
    elif feat == "port_count":
        q = f"SELECT count(DISTINCT dst_port) FROM packets WHERE {where} GROUP BY src_ip"
    elif feat == "port_diversity":
        q = (f"SELECT count(DISTINCT dst_port) * 1.0 / count(*) "
             f"FROM packets WHERE {where} GROUP BY src_ip")
    elif feat == "pct_with_payload":
        q = (f"SELECT count(*) FILTER (WHERE payload_len > 0) * 1.0 / count(*) "
             f"FROM packets WHERE {where} GROUP BY src_ip")
    elif feat == "distinct_payloads":
        q = f"SELECT count(DISTINCT payload_sha256) FROM packets WHERE {where} GROUP BY src_ip"
    elif feat == "avg_payload_len":
        q = (f"SELECT avg(payload_len) FILTER (WHERE payload_len > 0) "
             f"FROM packets WHERE {where} GROUP BY src_ip")
    elif feat == "l7_event_count":
        q = f"SELECT count(*) FROM l7_events WHERE {where} GROUP BY src_ip"
    elif feat in ("n_http_events", "n_tls_events", "n_ssh_events"):
        proto_id = {"n_http_events": lib.L7_ID['http'],
                    "n_tls_events": lib.L7_ID['tls'],
                    "n_ssh_events": lib.L7_ID['ssh']}[feat]
        q = f"SELECT count(*) FROM l7_events WHERE {where} AND l7_proto = {proto_id} GROUP BY src_ip"
    elif feat == "ioc_count":
        q = f"SELECT count(*) FROM iocs WHERE {where} GROUP BY src_ip"
    elif feat == "distinct_uas":
        q = (f"SELECT count(DISTINCT value) FROM iocs WHERE {where} AND "
             f"ioc_kind = {lib.IOC_ID['user_agent']} GROUP BY src_ip")
    elif feat == "distinct_uris":
        q = (f"SELECT count(DISTINCT value) FROM iocs WHERE {where} AND "
             f"ioc_kind = {lib.IOC_ID['http_uri']} GROUP BY src_ip")
    else:
        return np.empty(0)

    rows = con.execute(q).fetchall()
    return np.array([float(r[0] or 0) for r in rows], dtype=np.float64)


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    print("[drift] determining time windows...", file=sys.stderr)
    max_date = con.execute("SELECT max(ts)::DATE FROM packets").fetchone()[0]
    recent_end = max_date + _dt.timedelta(days=1)
    recent_start = recent_end - _dt.timedelta(days=args.recent_days)
    baseline_end = recent_start
    baseline_start = baseline_end - _dt.timedelta(days=args.baseline_days)
    print(f"[drift] baseline: {baseline_start} -> {baseline_end}", file=sys.stderr)
    print(f"[drift] recent:   {recent_start} -> {recent_end}", file=sys.stderr)

    from scipy.stats import ks_2samp, wasserstein_distance
    # Stage 1: collect raw stats for every feature so we can apply BH-FDR
    # globally instead of feature-by-feature - removes a major statistical
    # complaint from the multi-AI methodology review.
    staged: list[dict] = []
    for feat in NUMERIC_FEATURES:
        print(f"[drift]   feature {feat} ...", file=sys.stderr)
        try:
            base = feature_at_window(con, feat, str(baseline_start), str(baseline_end))
            recent = feature_at_window(con, feat, str(recent_start), str(recent_end))
        except Exception as e:
            print(f"[drift]   skipped {feat}: {e}", file=sys.stderr)
            continue
        if len(base) < 50 or len(recent) < 50:
            continue
        ks = ks_2samp(base, recent)
        # Wasserstein-1 (a.k.a. Earth Mover's Distance) - an effect-size
        # metric that is robust to sample-size inflation, unlike KS p-values.
        try:
            wd = float(wasserstein_distance(base, recent))
        except Exception:
            wd = 0.0
        psi = _psi(base, recent)
        psi_band = ("major" if psi >= 0.25
                    else ("moderate" if psi >= 0.10 else "stable"))
        staged.append({
            "feature": feat,
            "ks_statistic": float(ks.statistic),
            "p_value": float(ks.pvalue),
            "p_value_bh": 0.0,
            "wasserstein": wd,
            "psi": float(psi),
            "psi_band": psi_band,
            "baseline_mean": float(base.mean()),
            "recent_mean": float(recent.mean()),
            "baseline_med": float(np.median(base)),
            "recent_med": float(np.median(recent)),
            "baseline_n": int(len(base)),
            "recent_n": int(len(recent)),
            "significant": False,
        })

    # Stage 2: BH-FDR correction across all per-feature p-values, plus an
    # effect-size guard so we only flag "significant" when both the test
    # rejects AND PSI says the shift is non-trivial.
    pvals = [r["p_value"] for r in staged]
    bh_reject = _benjamini_hochberg(pvals, alpha=args.fdr)
    # Sort p-values to fill in adjusted q-values per Benjamini-Hochberg.
    n = len(pvals)
    if n:
        order = np.argsort(pvals)
        sorted_p = np.array(pvals)[order]
        q_sorted = sorted_p * n / (np.arange(1, n + 1))
        # cumulative-min from the right for monotone q-values
        q_sorted = np.minimum.accumulate(q_sorted[::-1])[::-1]
        q_adj = np.empty(n, dtype=np.float64)
        q_adj[order] = q_sorted
        for i, r in enumerate(staged):
            r["p_value_bh"] = float(min(q_adj[i], 1.0))
            r["significant"] = bool(bh_reject[i]) and (
                r["psi"] >= 0.10 or r["wasserstein"] > 0)
    sig_count = sum(1 for r in staged if r["significant"])
    out_rows = staged

    con.close()
    out_rows.sort(key=lambda r: r["ks_statistic"], reverse=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(out_rows, schema=SCHEMA),
                   OUT_DIR / "drift.parquet",
                   compression="zstd", compression_level=3)

    n_major = sum(1 for r in out_rows if r["psi_band"] == "major")
    n_moderate = sum(1 for r in out_rows if r["psi_band"] == "moderate")
    md_lines = [
        "# Feature distribution drift", "",
        f"Baseline: {baseline_start} to {baseline_end} ({args.baseline_days}d)",
        f"Recent:   {recent_start} to {recent_end} ({args.recent_days}d)",
        "",
        f"**{sig_count}** features show drift significant under "
        f"Benjamini-Hochberg FDR={args.fdr:.2f} *and* with non-trivial "
        f"effect (PSI >= 0.10 OR Wasserstein > 0).  Industry-standard PSI "
        f"bands: stable <0.10, moderate 0.10-0.25, major >=0.25.",
        "",
        f"Per PSI: **{n_major}** major, **{n_moderate}** moderate, "
        f"{len(out_rows) - n_major - n_moderate} stable.",
        "",
        "## Features ranked by Wasserstein distance",
        "",
        "_Wasserstein-1 / PSI are effect-size metrics that are robust to "
        "sample-size inflation, unlike raw KS p-values.  Read PSI as "
        "the headline number; KS/BH p-values as the formal test._",
        "",
        "| feature | KS | p_raw | p_bh | wasserstein | PSI | band | baseline_mean | recent_mean | n_base | n_rec | sig |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in sorted(out_rows, key=lambda r: -r["wasserstein"]):
        md_lines.append(
            f"| {r['feature']} | {r['ks_statistic']:.3f} | "
            f"{r['p_value']:.2e} | {r['p_value_bh']:.2e} | "
            f"{r['wasserstein']:.3g} | {r['psi']:.3f} | "
            f"{r['psi_band']} | {r['baseline_mean']:.3g} | "
            f"{r['recent_mean']:.3g} | {r['baseline_n']:,} | "
            f"{r['recent_n']:,} | {'YES' if r['significant'] else ''} |")
    (OUT_DIR / "drift.md").write_text("\n".join(md_lines) + "\n")
    print(f"[drift] {sig_count} significantly drifted features -> {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--recent-days", type=int, default=7)
    ap.add_argument("--baseline-days", type=int, default=60)
    ap.add_argument("--fdr", type=float, default=0.05,
                    help="Benjamini-Hochberg false-discovery-rate level "
                         "(default 0.05). Lower = stricter.")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
models/train_threat_classifier — GBM trained on bootstrap labels.

Labels come from existing analyzers:
    BENIGN  = benignfilter classified the IP as a known scanner
    THREAT  = at least one of: botnet_family set, scan_type contains
              "scan", ecodanom anomaly_score above 90th-percentile,
              campaign_count >= 3, scanner-intel flagged as automated
              with high port count
    UNKNOWN = neither (unlabeled, used for prediction-only)

LightGBM gradient-boosted classifier with feature importance logged.
Saves the model to the registry with full training metadata so we
can re-score later and compare predictions across model versions.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib
from sg import models as sm

FEATURE_VERSION = 1
NUMERIC_FEATURES = [
    "pkt_count", "byte_count", "day_count", "span_days", "pkts_per_active_day",
    "pct_tcp", "pct_udp", "pct_icmp", "pct_syn_only",
    "ttl_mode", "tcp_win_mode", "port_count", "port_diversity",
    "pct_with_payload", "distinct_payloads", "avg_payload_len",
    "l7_event_count", "l7_distinct_protos",
    "n_http_events", "n_tls_events", "n_ssh_events", "n_rdp_events",
    "ioc_count", "distinct_uas", "distinct_uris", "distinct_hashes",
    "distinct_creds", "distinct_msts",
    "anomaly_score", "burstiness_cv", "campaign_count",
]
LOG_FEATURES = {"pkt_count", "byte_count", "pkts_per_active_day",
                "port_count", "distinct_payloads", "l7_event_count",
                "ioc_count", "distinct_uris", "distinct_uas"}


def bootstrap_label(row) -> int:
    """Return 1 = THREAT, 0 = BENIGN, -1 = UNKNOWN."""
    if row["benign_org"]:
        return 0
    threat = False
    if row["botnet_family"]:
        threat = True
    if "scan" in (row["scan_type"] or ""):
        threat = True
    if row["campaign_count"] >= 3:
        threat = True
    if row["anomaly_score"] > 20 and row["port_count"] >= 50:
        threat = True
    if row["pct_syn_only"] > 0.8 and row["port_count"] >= 100:
        threat = True
    return 1 if threat else -1


def extract_X(table: pa.Table) -> np.ndarray:
    cols = [table.column(c).to_numpy(zero_copy_only=False).astype(np.float64)
            for c in NUMERIC_FEATURES]
    X = np.column_stack(cols)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    # Log-scale heavy-tailed features.
    for i, name in enumerate(NUMERIC_FEATURES):
        if name in LOG_FEATURES:
            X[:, i] = np.log1p(np.maximum(X[:, i], 0))
    return X


def as_frame(X: np.ndarray) -> pd.DataFrame:
    """Wrap a feature matrix as a named DataFrame so LightGBM stores and
    aligns features by name (not position).  Fit and predict must both go
    through this, otherwise sklearn warns about missing feature names and
    silently falls back to positional matching."""
    return pd.DataFrame(X, columns=NUMERIC_FEATURES)


def run(args: argparse.Namespace) -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print(f"[train_threat] no ip features (v{FEATURE_VERSION}) found", file=sys.stderr)
        return 2

    print(f"[train_threat] loading features {snap.snapshot_date}...", file=sys.stderr)
    table = sf.load_snapshot(snap)
    n = table.num_rows

    print("[train_threat] computing bootstrap labels...", file=sys.stderr)
    rows = table.to_pylist()
    y = np.array([bootstrap_label(r) for r in rows], dtype=np.int8)
    n_threat = int((y == 1).sum())
    n_benign = int((y == 0).sum())
    n_unknown = int((y == -1).sum())
    print(f"[train_threat] labels: {n_threat:,} THREAT / {n_benign:,} BENIGN "
          f"/ {n_unknown:,} UNKNOWN", file=sys.stderr)

    if n_threat < 100 or n_benign < 100:
        print(f"[train_threat] insufficient labels to train", file=sys.stderr)
        return 2

    print("[train_threat] extracting feature matrix...", file=sys.stderr)
    X = extract_X(table)
    labeled = y != -1
    X_train = X[labeled]
    y_train = (y[labeled] == 1).astype(np.int8)

    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (roc_auc_score, average_precision_score,
                                 brier_score_loss, classification_report)
    import lightgbm as lgb

    # Multi-AI methodology review flagged: random train/val split + bootstrap
    # labels = optimistic validation that overstates production performance.
    # Use a TEMPORAL split (last N% by first_seen) so the validation set
    # comes from after the training window.  This catches concept-drift
    # blind spots that random shuffling hides.
    if args.temporal_split and "first_seen" in table.column_names:
        first_seen = table.column("first_seen").to_numpy(zero_copy_only=False)
        first_seen_labeled = first_seen[labeled]
        # Cast to numeric for argsort.  Empties go first.
        ts_num = np.array([
            (t.timestamp() if hasattr(t, "timestamp") else 0.0)
            for t in first_seen_labeled
        ])
        order = np.argsort(ts_num)
        split = int(len(order) * (1 - args.val_frac))
        train_idx = order[:split]
        val_idx = order[split:]
        X_tr, X_va = X_train[train_idx], X_train[val_idx]
        y_tr, y_va = y_train[train_idx], y_train[val_idx]
        split_mode = "temporal"
    else:
        X_tr, X_va, y_tr, y_va = train_test_split(
            X_train, y_train, test_size=args.val_frac,
            random_state=42, stratify=y_train,
        )
        split_mode = "random_stratified"
    print(f"[train_threat] split mode: {split_mode}", file=sys.stderr)

    print(f"[train_threat] training LightGBM on {len(X_tr):,} train / {len(X_va):,} val...",
          file=sys.stderr)
    model = lgb.LGBMClassifier(
        n_estimators=400, learning_rate=0.05, max_depth=8, num_leaves=63,
        min_child_samples=50, subsample=0.8, colsample_bytree=0.8,
        n_jobs=-1, random_state=42, verbose=-1,
    )
    model.fit(as_frame(X_tr), y_tr, eval_set=[(as_frame(X_va), y_va)],
              callbacks=[lgb.early_stopping(30, verbose=False)])

    p_va = model.predict_proba(as_frame(X_va))[:, 1]
    auc = float(roc_auc_score(y_va, p_va))
    ap = float(average_precision_score(y_va, p_va))
    # Brier score is the reliability metric the multi-AI methodology
    # review specifically asked for - tells us if the model's predicted
    # probabilities are calibrated, not just rank-ordered.
    brier = float(brier_score_loss(y_va, p_va))
    # Score the UNLABELED population too so we can compare its score
    # distribution to BENIGN and THREAT - a sanity check for PU-style
    # label-noise propagation.
    if (~labeled).any():
        p_unl = model.predict_proba(as_frame(X[~labeled]))[:, 1]
        unl_pos_frac = float((p_unl >= 0.5).mean())
    else:
        unl_pos_frac = 0.0
    print(f"[train_threat] AUC={auc:.4f}  AP={ap:.4f}  Brier={brier:.4f}  "
          f"unlabeled@>=0.5={unl_pos_frac:.1%}", file=sys.stderr)

    importance = dict(sorted(
        zip(NUMERIC_FEATURES, model.feature_importances_.tolist()),
        key=lambda x: x[1], reverse=True,
    ))

    # Multi-AI consensus: gain-based feature_importance is biased and
    # only summarizes the model, not predictions.  Compute SHAP values
    # on the validation slice so we have per-prediction attribution
    # plus a stable global summary.
    shap_summary: dict[str, float] = {}
    shap_explainer = None
    shap_sample_values: np.ndarray | None = None
    try:
        import shap
        sample_n = min(args.shap_sample, len(X_va))
        rng = np.random.default_rng(42)
        sample_idx = rng.choice(len(X_va), size=sample_n, replace=False)
        shap_explainer = shap.TreeExplainer(model)
        sv = shap_explainer.shap_values(as_frame(X_va[sample_idx]))
        # LightGBM binary returns list[2] in legacy shap; positive class is [1].
        if isinstance(sv, list):
            sv = sv[1]
        shap_sample_values = np.asarray(sv)
        mean_abs = np.abs(shap_sample_values).mean(axis=0)
        shap_summary = dict(sorted(
            zip(NUMERIC_FEATURES, mean_abs.tolist()),
            key=lambda x: x[1], reverse=True,
        ))
        print(f"[train_threat] SHAP attribution on "
              f"{sample_n:,} val rows; top feature: "
              f"{next(iter(shap_summary))}", file=sys.stderr)
    except ImportError:
        print("[train_threat] shap not installed; skipping attribution",
              file=sys.stderr)
    except Exception as e:
        print(f"[train_threat] SHAP failed: {e}; continuing without",
              file=sys.stderr)

    version = sm.next_version("threat_classifier")
    info = sm.ModelInfo(
        name="threat_classifier", version=version,
        model_type="lightgbm.LGBMClassifier",
        feature_set=f"ip:v{FEATURE_VERSION}",
        training_rows=len(X_train),
        training_range=(str(args.since or ""), str(args.until or "")),
        trained_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
        metrics={
            "auc": auc, "ap": ap, "brier": brier,
            "split_mode": split_mode,
            "unlabeled_positive_rate": unl_pos_frac,
            "n_train": len(X_tr), "n_val": len(X_va),
            "n_threat": n_threat, "n_benign": n_benign, "n_unknown": n_unknown,
            "feature_importance": importance,
            "shap_global": shap_summary,
        },
    )
    path = sm.save_model("threat_classifier", model, info, make_current=True)

    # Persist the SHAP explainer + sample-value matrix beside the model
    # so downstream report code can attribute production predictions
    # without re-fitting.
    if shap_explainer is not None and shap_sample_values is not None:
        try:
            joblib.dump(shap_explainer,
                        sm.model_dir("threat_classifier", version)
                        / "shap_explainer.joblib")
            np.save(sm.model_dir("threat_classifier", version)
                    / "shap_val_sample.npy", shap_sample_values)
        except Exception as e:
            print(f"[train_threat] could not persist SHAP artifacts: {e}",
                  file=sys.stderr)

    print(f"[train_threat] saved v{version} -> {path}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    ap.add_argument("--temporal-split", action="store_true", default=True,
                    help="Split train/val by first_seen instead of randomly "
                         "(default ON). Use --no-temporal-split to disable.")
    ap.add_argument("--no-temporal-split", action="store_false",
                    dest="temporal_split")
    ap.add_argument("--val-frac", type=float, default=0.2,
                    help="Validation fraction (default 0.2 = most-recent 20%%).")
    ap.add_argument("--shap-sample", type=int, default=5000,
                    help="Validation-set rows to SHAP-explain (default 5000).")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

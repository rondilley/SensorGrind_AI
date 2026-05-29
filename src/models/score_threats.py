#!/usr/bin/env python3
"""
models/score_threats — score every IP with the current threat_classifier.

Loads the latest ip-feature snapshot, applies the current
threat_classifier model from the registry, and writes per-IP
threat probabilities to data/risk/threat_scores/.
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
from sg import features as sf
from sg import lib
from sg import models as sm

FEATURE_VERSION = 1
OUT_DIR = lib.OUTPUT_DIR / "risk" / "threat_scores"

SCHEMA = pa.schema([
    ("src_ip",         pa.string()),
    ("threat_score",   pa.float32()),
    ("model_version",  pa.uint16()),
    ("bootstrap_label", pa.int8()),
    ("scored_at",      pa.timestamp("us", tz="UTC")),
])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    args = ap.parse_args()

    loaded = sm.load_current("threat_classifier")
    if loaded is None:
        print("[score_threats] no current threat_classifier in registry", file=sys.stderr)
        return 2
    model, info = loaded
    print(f"[score_threats] using model v{info.version} (AUC={info.metrics.get('auc'):.4f})",
          file=sys.stderr)

    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[score_threats] no ip features", file=sys.stderr)
        return 2
    table = sf.load_snapshot(snap)
    print(f"[score_threats] scoring {table.num_rows:,} IPs...", file=sys.stderr)

    # local import to keep module-load light
    from models.train_threat_classifier import extract_X, bootstrap_label

    X = extract_X(table)
    probs = model.predict_proba(X)[:, 1]
    rows = table.to_pylist()
    labels = np.array([bootstrap_label(r) for r in rows], dtype=np.int8)

    out_rows = [{
        "src_ip": rows[i]["src_ip"],
        "threat_score": float(probs[i]),
        "model_version": info.version,
        "bootstrap_label": int(labels[i]),
        "scored_at": _dt.datetime.now(_dt.timezone.utc),
    } for i in range(len(rows))]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"scores_{snap.snapshot_date.isoformat()}.parquet"
    pq.write_table(pa.Table.from_pylist(out_rows, schema=SCHEMA),
                   out_path, compression="zstd", compression_level=3)

    high = sum(1 for r in out_rows if r["threat_score"] > 0.8)
    med = sum(1 for r in out_rows if 0.5 < r["threat_score"] <= 0.8)
    print(f"[score_threats] {high:,} high-threat (>0.8) + {med:,} medium (0.5-0.8) "
          f"-> {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

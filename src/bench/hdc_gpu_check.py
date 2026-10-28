#!/usr/bin/env python3
"""
bench/hdc_gpu_check — sg.hdc_gpu against the CPU HDC path on real days.

For each day D (with the neuro.py settings: 7 recorded fit days, seed
HDC_SEED, D = 8192, 128 prototypes per fit day), the check builds the
sessions once, then:

  1. encodes every chain with HDCEncoder.encode (numba) and with
     hdc_gpu.encode, and counts rows that differ (must be 0);
  2. runs hdc_eval.score_set (hdc_proto, hdc_drift) with device cpu and
     device gpu, with the time of each part;
  3. compares the per-source scores: hdc_drift must be identical (same
     vectors, same CPU code); hdc_proto is reported as max |diff|,
     Spearman rho and the overlap of the top 10 / 100 sources.

    python src/bench/hdc_gpu_check.py [--days D ...]

Output: output/reports/hdc_gpu/hdc_gpu_check.{json,md}
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import shutil
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import hdc, hdc_gpu, lib  # noqa: E402
from bench import baselines as bl, hdc_eval as he  # noqa: E402
import neuro  # noqa: E402

OUT = lib.OUTPUT_DIR / "reports" / "hdc_gpu"
DAYS = ("2024-02-10", "2024-08-15", "2025-03-15", "2026-06-30")
# proto time = score_set - _store - _drift (hdc.max_sim also runs inside
# hdc.prototypes, so it is not timed apart)
PARTS = (("he", "_store"), ("he", "_drift"))


def _timed(times: dict):
    """Wrap the PARTS so each call adds its wall time to ``times``."""
    mods = {"he": he}
    saved = []
    for m, f in PARTS:
        orig = getattr(mods[m], f)

        def wrap(*a, _o=orig, _k=f"{m}.{f}", **kw):
            t0 = time.perf_counter()
            try:
                return _o(*a, **kw)
            finally:
                times[_k] += time.perf_counter() - t0
        setattr(mods[m], f, wrap)
        saved.append((mods[m], f, orig))
    return saved


def _rank(v: np.ndarray) -> np.ndarray:
    r = np.empty(len(v))
    r[np.argsort(v, kind="stable")] = np.arange(len(v))
    return r


def check_day(day: str, tmp_root: Path) -> dict:
    d = _dt.date.fromisoformat(day)
    con = lib.duck(memory_limit="4GB", threads=2)
    lib.register_views(con)
    fit = bl._fit_days(con, d, 7)
    tmp = Path(tempfile.mkdtemp(prefix=f"gpucheck_{day}_", dir=tmp_root))
    try:
        t0 = time.perf_counter()
        s = he._sessions(con, fit + [d], 30, he._auto_buckets(con, fit + [d]), tmp)
        t_sess = time.perf_counter() - t0
        con.close()
        is_d = s["di"] == len(fit)
        iids = np.unique(s["iid"][is_d])
        ips = [s["ips"][i] for i in iids]
        chains = s["chains"]

        enc = hdc.HDCEncoder(neuro.HDC_SEED, hdc.D_DEFAULT)
        diff_rows, t_cpu_enc, t_gpu_enc = 0, 0.0, 0.0
        for a in range(0, len(chains), he.ENC_CHUNK):
            part = chains[a:a + he.ENC_CHUNK]
            t0 = time.perf_counter()
            c = enc.encode(part)
            t1 = time.perf_counter()
            g = hdc_gpu.encode(enc, part)
            t_gpu_enc += time.perf_counter() - t1
            t_cpu_enc += t1 - t0
            diff_rows += int((c != g).any(axis=1).sum())

        res = {"day": day, "chains": len(chains), "sessions": len(s["cid"]),
               "sources": len(ips), "sessions_s": t_sess,
               "encode_diff_rows": diff_rows,
               "encode_s": {"cpu": t_cpu_enc, "gpu": t_gpu_enc}}
        scores = {}
        for dev in ("cpu", "gpu"):
            a = argparse.Namespace(
                only=["hdc_proto", "hdc_drift"], dim=hdc.D_DEFAULT,
                noise_z=5.0, protos=128, alpha_fast=0.5, alpha_slow=0.05,
                min_sessions=3, align_power=4.0, align_weight="distinct",
                device=dev)
            times: dict = defaultdict(float)
            saved = _timed(times)
            try:
                t0 = time.perf_counter()
                scores[dev] = he.score_set(s, fit, ips, [neuro.HDC_SEED], a, tmp)[neuro.HDC_SEED]
                times["score_set"] = time.perf_counter() - t0
            finally:
                for m, f, o in saved:
                    setattr(m, f, o)
            res[f"score_set_s_{dev}"] = dict(times)
        c, g = scores["cpu"], scores["gpu"]
        res["drift_identical"] = bool(np.array_equal(c["hdc_drift"], g["hdc_drift"]))
        pc, pg = c["hdc_proto"], g["hdc_proto"]
        rho = float(np.corrcoef(_rank(pc), _rank(pg))[0, 1]) if len(pc) > 1 else 1.0
        top = {}
        for k in (10, 100):
            a_, b_ = set(np.argsort(-pc, kind="stable")[:k]), set(np.argsort(-pg, kind="stable")[:k])
            top[k] = len(a_ & b_) / max(1, min(k, len(pc)))
        res["proto"] = {"max_abs_diff": float(np.abs(pc - pg).max()) if len(pc) else 0.0,
                        "equal_frac": float(np.mean(pc == pg)) if len(pc) else 1.0,
                        "spearman": rho, "top10_overlap": top[10],
                        "top100_overlap": top[100]}
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def report(rows: list[dict]) -> str:
    L = ["# HDC GPU check", "",
         f"GPU: {hdc_gpu.torch.cuda.get_device_name(0)}.  Settings as neuro.py "
         "(7 fit days, seed 1, D = 8192, 128 prototypes per fit day).", "",
         "| Day | Chains | Encode rows that differ | Drift identical | "
         "Proto max diff | Proto Spearman | Top 10 | Top 100 |",
         "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        p = r["proto"]
        L.append(f"| {r['day']} | {r['chains']:,} | {r['encode_diff_rows']} | "
                 f"{r['drift_identical']} | {p['max_abs_diff']:.4f} | "
                 f"{p['spearman']:.4f} | {p['top10_overlap']:.2f} | {p['top100_overlap']:.2f} |")
    L += ["", "Time (s):", "",
          "| Day | Sessions | Encode CPU | Encode GPU | score_set CPU | score_set GPU | "
          "Proto CPU | Proto GPU | Drift |", "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        c, g = r["score_set_s_cpu"], r["score_set_s_gpu"]
        pc = c["score_set"] - c["he._store"] - c["he._drift"]
        pg = g["score_set"] - g["he._store"] - g["he._drift"]
        L.append(f"| {r['day']} | {r['sessions_s']:.1f} | {r['encode_s']['cpu']:.1f} | "
                 f"{r['encode_s']['gpu']:.1f} | {c['score_set']:.1f} | {g['score_set']:.1f} | "
                 f"{pc:.1f} | {pg:.1f} | {g.get('he._drift', 0):.1f} |")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days", nargs="+", default=list(DAYS))
    args = ap.parse_args()
    (lib.OUTPUT_DIR / ".hdc_tmp").mkdir(parents=True, exist_ok=True)
    rows = []
    for day in args.days:
        r = check_day(day, lib.OUTPUT_DIR / ".hdc_tmp")
        print(json.dumps(r), file=sys.stderr)
        rows.append(r)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "hdc_gpu_check.json").write_text(json.dumps(rows, indent=2))
    (OUT / "hdc_gpu_check.md").write_text(report(rows))
    print(report(rows))
    bad = sum(r["encode_diff_rows"] for r in rows) + sum(not r["drift_identical"] for r in rows)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

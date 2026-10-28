#!/usr/bin/env python3
"""
bench/hdc_gpu_gate — hdc_proto on the GPU path (sg.hdc_gpu) for the harness2
sets of module hdc_eval, saved as detector ``hdc_proto_gpu``.

The settings are those of the batch that made the stored ranks:
``hdc_eval.py --eval NAME --only ... --seed <set seed>`` (7 fit days, encoder
seed 1, D = 8192, 128 prototypes per fit day, noise floor z = 5), with
device gpu.  The tie-break seed of each set is its adversarysim seed, read
from output/logs/r2/<set>.log; with it, the cpu path gives the stored
hdc_proto ranks exactly (``--verify-cpu`` checks this per set).  The rows go into the
set's ranks file next to the cpu ``hdc_proto`` rows, which stay, so that the
gate can compare hdc_proto_gpu with rff_proto and with the cpu hdc_proto:

    python src/bench/hdc_gpu_gate.py [--sets NAME ...]
    python src/bench/harness2.py --summary hdc_eval <p3v2 sets> --tag gpu \\
        --twins '{"hdc_proto_gpu": ["rff_proto", "hdc_proto"]}'
    python src/bench/harness2.py --summary hdc_eval <p3ra sets> --tag devra_gpu \\
        --twins '{"hdc_proto_gpu": ["rff_proto", "hdc_proto"]}'

A set whose ranks file already has hdc_proto_gpu rows is skipped, so a
stopped run resumes.  hdc_eval.py itself is not changed: the neuro cache key
is a hash of it.
"""
from __future__ import annotations

import argparse
import re
import datetime as _dt
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import hdc, lib  # noqa: E402
from bench import baselines as bl, harness2, hdc_eval as he  # noqa: E402
import neuro  # noqa: E402

DET = "hdc_proto_gpu"
LOGS = lib.OUTPUT_DIR / "logs" / "r2"


def tie_seed(name: str) -> int:
    """The --seed of the batch that scored the set (its adversarysim seed)."""
    m = re.search(r"seed=(\d+)", (LOGS / f"{name}.log").read_text())
    if not m:
        raise SystemExit(f"[hdc_gpu_gate] no seed in {LOGS / name}.log")
    return int(m.group(1))


def ranks_path(name: str) -> Path:
    return harness2.OUT / "hdc_eval" / f"{name}_ranks.parquet"


def all_sets() -> list[str]:
    return sorted(p.name.removesuffix("_ranks.parquet")
                  for p in (harness2.OUT / "hdc_eval").glob("*_ranks.parquet"))


def done(name: str) -> bool:
    p = ranks_path(name)
    return p.exists() and DET in set(pq.read_table(p, columns=["detector"])
                                     .column("detector").to_pylist())


def score(name: str, verify_cpu: bool = False) -> None:
    seed = tie_seed(name)
    con = lib.duck()
    lib.register_eval_views(con, name)
    truth = con.execute("SELECT * FROM eval_truth").to_arrow_table().to_pylist()
    day = min(t["start_ts"] for t in truth).astimezone(_dt.timezone.utc).date()
    fit = bl._fit_days(con, day, 7)
    ips = he._population(con, day)
    (lib.OUTPUT_DIR / ".hdc_tmp").mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=f"gpugate_{name}_",
                                dir=lib.OUTPUT_DIR / ".hdc_tmp"))
    try:
        s = neuro._sessions_retry(con, he, fit + [day], tmp, name)
        con.close()
        a = argparse.Namespace(
            only=["hdc_proto"], dim=hdc.D_DEFAULT, noise_z=5.0, protos=128,
            alpha_fast=0.5, alpha_slow=0.05, min_sessions=3, align_power=4.0,
            align_weight="distinct", device="gpu")
        sc = he.score_set(s, fit, ips, [neuro.HDC_SEED], a, tmp)[neuro.HDC_SEED]
        if verify_cpu:
            a.device = "cpu"
            cpu = he.score_set(s, fit, ips, [neuro.HDC_SEED], a, tmp)[neuro.HDC_SEED]
            key = lambda r: (r["src_ip"], r["archetype"], r["rank_clean"], r["rank_all"])
            new = sorted(map(key, harness2.truth_ranks(
                name, day, ips, {"hdc_proto": cpu["hdc_proto"]}, truth, seed)), key=str)
            old = sorted((key(r) for r in pq.read_table(ranks_path(name)).to_pylist()
                          if r["detector"] == "hdc_proto"), key=str)
            if new != old:
                raise SystemExit(f"[hdc_gpu_gate] {name}: cpu hdc_proto does not "
                                 "reproduce the stored ranks")
            print(f"[hdc_gpu_gate] {name}: cpu hdc_proto = stored ranks", file=sys.stderr)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        import torch
        torch.cuda.empty_cache()
    ranks = harness2.truth_ranks(name, day, ips, {DET: sc["hdc_proto"]},
                                 truth, seed)
    old = pq.read_table(ranks_path(name)).to_pylist()
    harness2.write_ranks("hdc_eval", name,
                         [r for r in old if r["detector"] != DET] + ranks)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sets", nargs="*")
    ap.add_argument("--verify-cpu", action="store_true",
                    help="also run the cpu path and require the stored ranks")
    args = ap.parse_args()
    sets = args.sets or all_sets()
    todo = [n for n in sets if not done(n)]
    print(f"[hdc_gpu_gate] {len(sets)} sets, {len(sets) - len(todo)} done, "
          f"{len(todo)} to score", file=sys.stderr)
    t0 = time.time()
    for i, name in enumerate(todo, 1):
        score(name, args.verify_cpu)
        print(f"[hdc_gpu_gate] {i}/{len(todo)} {name} {time.time() - t0:.0f}s",
              file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

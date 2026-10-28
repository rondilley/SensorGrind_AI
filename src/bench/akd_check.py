#!/usr/bin/env python3
"""
bench/akd_check — bit-exact check of sg.akd against libakida on real windows.

Neuromorphic round 2 plan §6 (AKD1500 bench).  For each test day, each
source with at least 20 packets gives one 48-value window: a 32-bin
histogram of log10 inter-arrival times (1 ms .. 100 000 s, 4 bins per
decade) and a 16-bin histogram of dst_port % 16, each count stored as
min(15, round(log2(1 + n))) (uint4).

For each day, seed and (weights_bits, act_bits) pair, the check builds
InputData -> FullyConnected(16) through sg.akd, fills it with seeded
weights, thresholds and act_steps (parameters, not data), runs
Model.forward in libakida, and compares every output with
sg.akd.fc_reference.  It then maps the model on the virtual AKD1500 (one
Hardware sequence expected; a virtual device cannot run it, the card is
needed for that) and checks that a to_bytes/from_bytes copy of the mapped
model gives the same outputs in software.  When the driver finds an
AKD1500 card, the copy is also mapped on the card (one Hardware sequence
expected) and its forward on the card must equal the software output.
Any mismatch is an error.

    python src/bench/akd_check.py [--days D ...] [--seeds N]
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import duckdb
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import akd  # noqa: E402

PACKETS = Path("output/parquet/packets")
DAYS = ("2024-02-10", "2024-08-15", "2025-03-01", "2026-06-30")
BITS = ((4, 4), (4, 2), (4, 1), (2, 4), (2, 2), (2, 1), (1, 4), (1, 2), (1, 1))
UNITS = 16


def windows(day: str) -> np.ndarray:
    q = f"""
    with p as (select src_ip, epoch(ts) t, dst_port
               from read_parquet('{PACKETS}/dt={day}/*.parquet')),
    g as (select src_ip, t - lag(t) over (partition by src_ip order by t) iat,
                 dst_port from p),
    s as (select src_ip from p group by 1 having count(*) >= 20)
    select list(least(31, greatest(0, floor((log10(greatest(iat, 1e-3)) + 3) * 4)))::int)
             filter (where iat is not null),
           list((dst_port % 16)::int) filter (where dst_port is not null)
    from g join s using (src_ip) group by src_ip order by src_ip"""
    rows = duckdb.sql(q).fetchall()
    x = np.zeros((len(rows), 48), np.int64)
    for i, (ib, pb) in enumerate(rows):
        np.add.at(x[i], ib, 1)
        np.add.at(x[i], [32 + v for v in pb], 1)
    return np.minimum(15, np.round(np.log2(1 + x))).astype(np.uint8)


def build(wb: int, ab: int, seed: int) -> tuple[akd.Model, dict]:
    rng = np.random.default_rng(seed)
    m = akd.Model()
    m.add(akd.input_layer(48))
    fc = akd.fully_connected(UNITS, weights_bits=wb, act_bits=ab, name="fc")
    m.add(fc)
    lo, hi = {4: (-7, 7), 2: (-1, 1), 1: (0, 1)}[wb]
    p = {"weights": rng.integers(lo, hi + 1, fc.get_variable("weights").shape).astype(np.int8),
         "threshold": rng.integers(0, 60, UNITS).astype(np.int32),
         "act_step": rng.uniform(0.5, 16, UNITS).astype(np.float32)}
    for k, v in p.items():
        fc.set_variable(k, v)
    return m, p


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days", nargs="+", default=list(DAYS))
    ap.add_argument("--seeds", type=int, default=3)
    args = ap.parse_args()

    print(f"[akd_check] libakida {akd.__version__}, hardware devices: {akd.devices()}")
    dev = akd.AKD1500()
    cards = akd.devices()
    total = bad = 0
    t_card = 0.0
    for day in args.days:
        x = windows(day)
        x4 = x.reshape(-1, 1, 1, 48)
        for seed in range(args.seeds):
            for wb, ab in BITS:
                m, p = build(wb, ab, seed)
                out = m.forward(x4).reshape(len(x), UNITS)
                ref = akd.fc_reference(x, p["weights"], p["threshold"], p["act_step"], ab)
                n = int((out != ref).sum())
                m.map(dev)
                if [s.backend.name for s in m.sequences] != ["Hardware"]:
                    n += 1
                copy = akd.Model.from_bytes(m.to_bytes()).forward(x4).reshape(len(x), UNITS)
                n += int((copy != out).sum())
                if cards:
                    hw = akd.Model.from_bytes(m.to_bytes())
                    hw.map(cards[0])
                    if [s.backend.name for s in hw.sequences] != ["Hardware"]:
                        n += 1
                    t0 = time.perf_counter()
                    hw_out = hw.forward(x4).reshape(len(x), UNITS)
                    t_card += time.perf_counter() - t0
                    n += int((hw_out != out).sum())
                total += out.size
                bad += n
                if n:
                    print(f"  MISMATCH {day} seed={seed} w{wb}a{ab}: {n}")
        seqs = [(s.name, s.backend.name) for s in m.sequences]
        print(f"[akd_check] {day}: {len(x)} sources, last map {seqs}")
    ways = 3 if cards else 2
    print(f"[akd_check] {total} outputs, each checked {ways} ways, {bad} mismatches")
    if cards:
        print(f"[akd_check] card forward {t_card:.3f} s, "
              f"{1e6 * t_card / (total / UNITS):.1f} us/window")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()

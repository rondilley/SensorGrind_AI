#!/usr/bin/env python3
"""
bench/efficiency — cost and speed of the neuromorphic detectors against
their classical twins, on the real corpus.

Neuromorphic plan, all phases (docs/ARCHITECTURE.md §9).  The gate runs ask
"does it find more?"; this bench asks "does it find the same thing faster,
or with fewer resources?".  Parts (``--part``, default all, in this order):

  arrival   Phase 2: exclusive wall and CPU seconds of each detector over
            every day of arrival_series (arrival_eval.run_detectors with a
            Clock, then each external detector), checked against the saved
            arrival_scores_full.parquet; the state each gate detector keeps
            between days (from the array shapes); minutes from each event
            start to the first alarm at 1 and 10 alarm minutes per day.
  lif       Phase 3: for every recorded day, seconds of median_iat, the LIF
            bank, the untrained bank, the Hawkes EM fit, pacing as the
            harness runs it (Python loop) and pacing compiled (numba, same
            arithmetic, checked equal); the state each detector must hold
            to score one source online.
  latency   Phase 3: recall@k of lif, lif_nocal, pacing and pacing_cal when
            D and its fit days are cut to their first H hours (UTC), on
            every p3t_* injection set.  Recall is over all injected sources
            of the archetype: a source with too few packets by hour H is a
            miss.
  stdp      Phase 5: seconds of STDP training and novelty against k-means
            fit and novelty, on every p3t_* set day.
  hdc       Phase 1: encode seconds of every distinct timed chain
            (chainfp_timed.parquet), hdc against rff and the exact-string
            hash of string_rarity; bytes per vector; 1-NN search seconds of
            the int8 vectors as float32 products (the hdc_eval method), of
            the same vectors as packed bits (XOR + popcount, the same
            cosine), and of rff.

Run every numeric library on one thread (OMP_NUM_THREADS, OPENBLAS_NUM_THREADS,
MKL_NUM_THREADS and NUMBA_NUM_THREADS = 1).  The pools then run one detector
per process, and CPU seconds are the resource.  Numba compile time is
paid before the clocks start.

Output: output/reports/efficiency/efficiency_<part>.{parquet,md}
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
from numba import njit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import hdc, lib, lif, stdp
from bench import arrival_eval as ae
from bench import baselines as bl
from bench import lif_eval as le
from bench import stdp_eval as se

OUT = lib.REPORTS / "efficiency"
PARTS = ("arrival", "lif", "latency", "stdp", "hdc")
HOURS = (1, 2, 4, 8, 12, 24)
LIF_STATE_ARRAYS = 7          # v, mf, ms, qs, sp, sp2, nreg in lif._bank
CHAIN_CHUNK = 50_000

SCHEMA = pa.schema([
    ("part",     pa.string()),
    ("detector", pa.string()),
    ("metric",   pa.string()),
    ("value",    pa.float64()),
])


def _row(part, det, metric, value) -> dict:
    return {"part": part, "detector": det, "metric": metric,
            "value": float(value)}


def _clock(f, *a, **kw):
    """(result, wall s, cpu s) of one call."""
    w, c = time.perf_counter(), time.process_time()
    r = f(*a, **kw)
    return r, time.perf_counter() - w, time.process_time() - c


def _write(part: str, rows: list[dict], md: list[str]) -> None:
    paths = lib.Report(name="efficiency", rows=rows, schema=SCHEMA,
                       markdown="\n".join(md) + "\n").write(suffix=part)
    print(f"[efficiency] wrote {paths['markdown']}", file=sys.stderr)


def _p3_sets() -> list[str]:
    return sorted(p.name for p in (lib.EVAL_DIR / "inject").glob("p3t_*"))


# ---------------------------------------------------------------- arrival

def _arrival_state_bytes() -> dict:
    """Bytes each gate detector keeps between days (array shapes)."""
    C = len(ae.COLS)
    f_lin = 1 + ae.LAGS * C + 2
    f_q = f_lin + ae.quad_features(np.zeros((1, ae.LAGS * C))).shape[1]
    day = 1440 * C * 8
    hist = ae.HIST_DAYS * day
    return {
        "ngrc_htm": ae.FIT_DAYS * (f_q * f_q + f_q * C) * 8 + hist,
        "ar_htm": ae.FIT_DAYS * (f_lin * f_lin + f_lin * C) * 8 + hist,
        "untrained_htm": ae.FIT_DAYS * (24 * C + 24) * 8 + hist,
        "stl_z": ae.FIT_DAYS * 1440 * 5 * 8,
        "hawkes": ae.FIT_DAYS * 1440 * 2 * 8,
        "features_ngrc": f_q, "features_ar": f_lin,
    }


def part_arrival(args) -> None:
    P = "arrival"
    mm = pq.read_table(ae.SERIES, columns=["minute"])["minute"]
    start, end = (v.as_py().date() for v in (mm[0], mm[-1]))
    if args.max_days:
        end = min(end, start + _dt.timedelta(days=args.max_days - 1))
    g = ae.load_grid(start, end)
    clock = ae.Clock()
    t0 = time.time()
    res = ae.run_detectors(g, clock=clock)
    sc, ok, minute = res["scores"], res["ok"], g["minute"]
    ext = [("midas_r", lambda: ae.midas_scores(g, start, ok)),
           ("hst", lambda: ae.hst_scores(g, ok)),
           ("deeplog", lambda: ae.deeplog_scores(g, ok)),
           ("markov", lambda: ae.markov_scores(g, start, ok)),
           ("som", lambda: ae.som_scores(g, ok)),
           ("rrcf", lambda: ae.rrcf_scores(g, ok))]
    for name, f in ext:
        with clock.time(name):
            sc[name] = f()
    with clock.time("cms+hll"):
        sc["cms"], sc["hll"], _ = ae.sketch_scores(g, start, ok)
    print(f"[efficiency] arrival detectors {time.time() - t0:.0f}s",
          file=sys.stderr)

    # the clocks must not change a score: compare with the saved run
    saved = pq.read_table(ae.OUT / "arrival_scores_full.parquet")
    sm = saved["minute"].cast(pa.int64()).to_numpy() / 1e6
    inside = sm <= minute[-1]
    saved, sm = saved.filter(pa.array(inside)), sm[inside]
    idx = np.searchsorted(minute, sm)
    same = {}
    for k in ae.DETECTORS:
        a = sc[k][idx]
        b = saved[k].to_numpy(zero_copy_only=False).astype(float)
        fa, fb = np.isfinite(a), np.isfinite(b)
        both = fa & fb
        rel = (np.abs(a[both] - b[both]) / np.maximum(1.0, np.abs(b[both]))
               if both.any() else np.zeros(1))
        same[k] = (int((fa != fb).sum()), float(rel.max()))

    rows: list[dict] = []
    n_min = {k: int(np.isfinite(sc[k]).sum()) for k in ae.DETECTORS}
    order = sorted(clock.cpu, key=lambda k: -clock.cpu[k])
    md = [f"- days {start} to {end}: {g['n_days']:,} days, "
          f"{len(minute):,} minutes; every library on one thread", "",
          "## Seconds for each detector (all days)", "",
          "`inputs` is the lag matrix that the NG-RC and AR readouts share. "
          "`diagnostic` is the ridge sweep of the one-step error table. The "
          "`midas_r`, `markov` and `cms+hll` seconds include their DuckDB "
          "queries of the packets, one or more for each day.", "",
          "| detector | wall s | CPU s | scored minutes | CPU µs per minute "
          "| max relative change against the saved scores | finite/NaN changes |",
          "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for k in order:
        dets = ("cms", "hll") if k == "cms+hll" else (k,)
        nm = max(n_min.get(d, 0) for d in dets) if k in n_min or k == "cms+hll" else 0
        per = clock.cpu[k] / nm * 1e6 if nm else float("nan")
        chg = [same[d] for d in dets if d in same]
        c1 = f"{max(c[1] for c in chg):.1e}" if chg else ""
        c0 = f"{sum(c[0] for c in chg)}" if chg else ""
        md.append(f"| {k} | {clock.wall[k]:.1f} | {clock.cpu[k]:.1f} | "
                  f"{nm:,} | {per:.1f} | {c1} | {c0} |")
        rows += [_row(P, k, "wall_s", clock.wall[k]),
                 _row(P, k, "cpu_s", clock.cpu[k]),
                 _row(P, k, "scored_minutes", nm)]
        for c in chg:
            rows += [_row(P, k, "max_rel_change", c[1]),
                     _row(P, k, "finite_changes", c[0])]

    stb = _arrival_state_bytes()
    md += ["", "## State kept between days (from the array shapes)", "",
           f"NG-RC features: {stb['features_ngrc']}, AR features: "
           f"{stb['features_ar']} ({len(ae.COLS)} series, {ae.LAGS} lags).", "",
           "| detector | bytes |", "| --- | ---: |"]
    for k in ("ngrc_htm", "ar_htm", "untrained_htm", "stl_z", "hawkes"):
        md.append(f"| {k} | {stb[k]:,} |")
        rows.append(_row(P, k, "state_bytes", stb[k]))

    # detection delay at fixed alarm budgets, on the gate's common minutes
    ev = {k: (_dt.datetime.fromisoformat(a).timestamp(),
              _dt.datetime.fromisoformat(b).timestamp())
          for k, (a, b) in ae.EVENTS.items()}
    common = np.all(np.stack([np.isfinite(sc[k]) for k in ae.GATE]), axis=0)
    md += ["", "## Minutes from the event start to the first alarm", "",
           "The threshold is the score quantile that gives the stated number "
           "of alarm minutes each day. `-` = no alarm in the event. `n/s` = "
           "no scored minute in the event.", "",
           "| detector | budget | " + " | ".join(ev) + " |",
           "| --- | ---: |" + " ---: |" * len(ev)]
    for k in ae.DETECTORS:
        v = np.where(common, sc[k], np.nan)
        fin = np.isfinite(v)
        for rate in (1, 10):
            th = np.quantile(v[fin], 1 - rate / 1440) if fin.any() else np.inf
            cells = []
            for e, (a, b) in ev.items():
                w = (minute + 60 > a) & (minute < b) & fin
                hit = w & (v >= th)
                if not w.any():
                    cells.append("n/s")
                elif not hit.any():
                    cells.append("-")
                else:
                    dly = max(0.0, (minute[hit].min() - a) / 60)
                    cells.append(f"{dly:.0f}")
                    rows.append(_row(P, k, f"delay_min_{e}_rate{rate}", dly))
            md.append(f"| {k} | {rate}/day | " + " | ".join(cells) + " |")
    _write(P, rows, md)


# ---------------------------------------------------------------- lif

@njit(cache=True)
def _pacing_nb(t, seg, starts):
    """bench/lif_eval._pacing, compiled (the same arithmetic)."""
    S = len(starts) - 1
    cv = np.zeros(S)
    split = np.zeros(S)
    for s in range(S):
        a, b = starts[s], starts[s + 1]
        m = 0
        for i in range(a + 1, b):
            if seg[i] == seg[i - 1]:
                m += 1
        if m < 4:
            continue
        dd = np.empty(m)
        j = 0
        for i in range(a + 1, b):
            if seg[i] == seg[i - 1]:
                dd[j] = t[i] - t[i - 1]
                j += 1
        mu = dd.mean()
        if mu > 0:
            cv[s] = -np.log(max(dd.std() / mu, 1e-6))
        h = m // 2
        m1, m2 = np.median(dd[:h]), np.median(dd[h:])
        split[s] = abs(np.log(max(m2, 1e-3) / max(m1, 1e-3)))
    return cv, split


_WARM = False


def _warm() -> None:
    """Compile every kernel before a clock starts."""
    global _WARM
    if _WARM:
        return
    t = np.cumsum(np.full(64, 3.0))
    seg = np.zeros(64, dtype=np.int64)
    st = np.array([0, 64])
    med = lif.median_iat(t, seg, st)
    lif.bank_scores(t, seg, st, med)
    lif.bank_scores(t, seg, st, med, taus=np.sort(lif.TAUS[::-1].copy()),
                    band=(0.0, np.inf), change_band=(0.0, np.inf), adapt=False)
    lif.hawkes_scores(t, seg, st, med)
    _pacing_nb(t, seg, st)
    _WARM = True


def _utaus(seed: int) -> np.ndarray:
    return np.sort(np.exp(np.random.default_rng(seed).uniform(
        np.log(0.01), np.log(864000.0), len(lif.TAUS))))


def _load(day: _dt.date, min_pkts: int, eval_name: str | None):
    con = lib.duck(memory_limit="3GB", threads=1)
    if eval_name:
        lib.register_eval_views(con, eval_name)
    else:
        lib.register_views(con)
    mask_ends = np.array(sorted(e.timestamp() for _, e, _ in
                                lib.load_sensor_mask()))
    d = le.load_day(con, day, min_pkts, mask_ends)
    con.close()
    return d


def _lif_day(day: str, min_pkts: int, seed: int) -> dict | None:
    _warm()
    d, lw, lc = _clock(_load, _dt.date.fromisoformat(day), min_pkts, None)
    if not len(d["ips"]):
        return None
    t, seg, st = d["t"], d["seg"], d["starts"]
    out = {"day": day, "S": len(d["ips"]), "N": int(d["n"].sum()),
           "n_max": int(d["n"].max()), "load": (lw, lc)}
    med, *out["median_iat"] = _clock(lif.median_iat, t, seg, st)
    _, *out["lif"] = _clock(lif.bank_scores, t, seg, st, med)
    _, *out["untrained_lif"] = _clock(
        lif.bank_scores, t, seg, st, med, taus=_utaus(seed),
        band=(0.0, np.inf), change_band=(0.0, np.inf), adapt=False)
    _, *out["hawkes"] = _clock(lif.hawkes_scores, t, seg, st, med)
    (cv, sp, _), *out["pacing_py"] = _clock(le._pacing, t, seg, st)
    (cv2, sp2), *out["pacing_nb"] = _clock(_pacing_nb, t, seg, st)
    out["pacing_diff"] = float(max(np.abs(cv - cv2).max(), np.abs(sp - sp2).max()))
    return out


def _recorded_days() -> list[str]:
    return sorted(p.name[3:] for p in (lib.PARQUET / "packets").glob("dt=*"))


def part_lif(args) -> None:
    P = "lif"
    days = _recorded_days()[:args.max_days or None]
    t0 = time.time()
    res = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for i, r in enumerate(pool.map(_lif_day, days,
                                       [args.min_pkts] * len(days),
                                       [args.seed] * len(days))):
            if r:
                res.append(r)
            if (i + 1) % 100 == 0:
                print(f"[efficiency] lif {i + 1}/{len(days)} "
                      f"{time.time() - t0:.0f}s", file=sys.stderr)
    S = sum(r["S"] for r in res)
    N = sum(r["N"] for r in res)
    dets = ("load", "median_iat", "lif", "untrained_lif", "hawkes",
            "pacing_py", "pacing_nb")
    rows = [_row(P, "all", "source_days", S), _row(P, "all", "packets", N),
            _row(P, "all", "days", len(res))]
    md = [f"- {len(res)} recorded days, {S:,} source-days with >= "
          f"{args.min_pkts} unmasked packets, {N:,} packets; one thread per "
          f"process, {args.workers} processes", "",
          "## Seconds for each detector (sum of all days)", "",
          "`lif` is the bank only. It needs `median_iat` first, so the full "
          "cost of `lif` is the sum of the two rows. `pacing_py` is the "
          "Python loop of bench/lif_eval. `pacing_nb` is the same arithmetic "
          f"compiled by numba (largest difference "
          f"{max(r['pacing_diff'] for r in res):.1e}).", "",
          "| detector | wall s | CPU s | CPU ns per packet | CPU µs per source |",
          "| --- | ---: | ---: | ---: | ---: |"]
    for k in dets:
        w = sum(r[k][0] for r in res)
        c = sum(r[k][1] for r in res)
        md.append(f"| {k} | {w:.1f} | {c:.1f} | {c / N * 1e9:.1f} | "
                  f"{c / S * 1e6:.1f} |")
        rows += [_row(P, k, "wall_s", w), _row(P, k, "cpu_s", c)]
    lif_b = len(lif.TAUS) * LIF_STATE_ARRAYS * 8 + 4 * 8
    n_max = max(r["n_max"] for r in res)
    md += ["", "## State to score one source online", "",
           f"The LIF bank keeps {LIF_STATE_ARRAYS} values for each of its "
           f"{len(lif.TAUS)} neurons, plus 4 counters: {lif_b:,} bytes for "
           "each source, for all packet counts. `pacing` (median and standard "
           "deviation of the IATs, medians of the two halves) and the Hawkes "
           "EM fit need every packet time of the source: 8 bytes for each "
           "packet. The `lif` band is set by the median IAT, which also needs "
           "every packet time. Only `untrained_lif` (all neurons, no band) "
           "is fully online.", "",
           "| detector | bytes for all source-days | bytes for the largest source |",
           "| --- | ---: | ---: |",
           f"| lif bank | {S * lif_b:,} | {lif_b:,} |",
           f"| pacing, hawkes, median IAT | {N * 8:,} | {n_max * 8:,} |"]
    rows += [_row(P, "lif", "state_bytes_per_source", lif_b),
             _row(P, "pacing", "state_bytes_total", N * 8),
             _row(P, "lif", "state_bytes_total", S * lif_b),
             _row(P, "pacing", "state_bytes_largest_source", n_max * 8)]
    _write(P, rows, md)


# ---------------------------------------------------------------- latency

def _prefix(d: dict, cutoff: float, min_pkts: int) -> dict:
    """The sources of d with >= min_pkts packets before ``cutoff``."""
    src = np.repeat(np.arange(len(d["n"])), d["n"])
    keep = d["t"] < cutoff
    cnt = np.bincount(src[keep], minlength=len(d["n"]))
    ok = cnt >= min_pkts
    sel = keep & ok[src]
    n = cnt[ok]
    return {"ips": [ip for ip, k in zip(d["ips"], ok) if k],
            "t": d["t"][sel], "seg": d["seg"][sel],
            "starts": np.r_[0, np.cumsum(n)], "n": n}


def _latency_readouts(day: str, min_pkts: int, eval_name: str | None
                      ) -> tuple[str, str | None, dict]:
    _warm()
    dd = _dt.date.fromisoformat(day)
    d = _load(dd, min_pkts, eval_name)
    t0 = _dt.datetime.combine(dd, _dt.time(), _dt.timezone.utc).timestamp()
    out = {}
    for h in HOURS:
        p = _prefix(d, t0 + 3600 * h, min_pkts) if len(d["ips"]) else d
        if not len(p["ips"]):
            out[h] = None
            continue
        t, seg, st = p["t"], p["seg"], p["starts"]
        med = lif.median_iat(t, seg, st)
        ch, rg = lif.bank_scores(t, seg, st, med)
        cv, sp = _pacing_nb(t, seg, st)
        out[h] = {"change": ch, "reg": np.where(np.isfinite(rg), rg, -1e9),
                  "cv": cv, "split": sp, "logn": np.log(p["n"]),
                  "ips": p["ips"] if eval_name else None}
    return day, eval_name, out


def part_latency(args) -> None:
    P = "latency"
    sets = _p3_sets()[:args.max_sets or None]
    con = lib.duck()
    lib.register_views(con)
    plan = {}
    for name in sets:
        tr = pq.read_table(lib.eval_inject_dir(name) / "truth.parquet").to_pylist()
        day = min(t["start_ts"] for t in tr).astimezone(_dt.timezone.utc).date()
        plan[name] = (day, bl._fit_days(con, day, args.fit_days), tr)
    con.close()
    fit_days = sorted({str(f) for _, fd, _ in plan.values() for f in fd})
    jobs = [(d, None) for d in fit_days] + [(str(v[0]), n) for n, v in plan.items()]
    t0 = time.time()
    fit_ro: dict[str, dict] = {}
    d_ro: dict[str, dict] = {}
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futs = [pool.submit(_latency_readouts, d, args.min_pkts, n) for d, n in jobs]
        for i, f in enumerate(futs):
            day, name, ro = f.result()
            (d_ro if name else fit_ro)[name or day] = ro
            if (i + 1) % 100 == 0:
                print(f"[efficiency] latency {i + 1}/{len(jobs)} "
                      f"{time.time() - t0:.0f}s", file=sys.stderr)
    dets = ("lif", "lif_nocal", "pacing", "pacing_cal")
    hits: dict[tuple, int] = {}
    total: dict[str, int] = {}
    for name, (day, fdays, tr) in plan.items():
        src_truth = [t for t in tr if t["level"] == "source" and not t["is_control"]]
        for t in src_truth:
            total[t["archetype"]] = total.get(t["archetype"], 0) + 1
        for h in HOURS:
            dr = d_ro[name][h]
            parts = [fit_ro[str(f)][h] for f in fdays if fit_ro[str(f)][h]]
            if dr is None or not parts:
                continue
            fit = {k: np.concatenate([p[k] for p in parts])
                   for k in ("change", "reg", "cv", "split", "logn")}
            cal = lambda k: lif.calibrate(dr[k], dr["logn"], fit[k], fit["logn"])
            own = lambda k: lif.calibrate(dr[k], dr["logn"], dr[k], dr["logn"],
                                          n_bins=1)
            sc = {"lif": np.maximum(cal("change"), cal("reg")),
                  "lif_nocal": np.maximum(own("change"), own("reg")),
                  "pacing": np.maximum(own("cv"), own("split")),
                  "pacing_cal": np.maximum(cal("cv"), cal("split"))}
            for r in le.eval_clean(name, dr["ips"], sc, tr, args.source_k,
                                   args.seed):
                if r["is_control"]:
                    continue
                key = (r["detector"], r["archetype"], h, r["k"])
                hits[key] = hits.get(key, 0) + r["hits"]
    rows: list[dict] = []
    md = [f"- {len(plan)} sets, fit window {args.fit_days} recorded days, "
          f">= {args.min_pkts} packets before hour H; readouts of "
          f"{len(jobs)} day loads in {time.time() - t0:.0f} s", "",
          "D and each fit day are cut at the same hour H after 00:00 UTC. "
          "Recall is over all injected sources of the archetype. A source "
          "with fewer packets than the limit before hour H is a miss.", ""]
    for arch in ("jittered_beacon", "rhythm_change"):
        if arch not in total:
            continue
        for k in args.source_k:
            md += [f"## {arch}, k = {k} ({total[arch]} sources)", "",
                   "| detector | " + " | ".join(f"{h} h" for h in HOURS) + " |",
                   "| --- |" + " ---: |" * len(HOURS)]
            for det in dets:
                cells = []
                for h in HOURS:
                    rc = hits.get((det, arch, h, k), 0) / total[arch]
                    cells.append(f"{rc:.2f}")
                    rows.append(_row(P, det, f"recall_{arch}_k{k}_h{h}", rc))
                md.append(f"| {det} | " + " | ".join(cells) + " |")
            md.append("")
    _write(P, rows, md)


# ---------------------------------------------------------------- stdp

def part_stdp(args) -> None:
    P = "stdp"
    import scipy.sparse as sps
    from sklearn.cluster import MiniBatchKMeans
    sets = _p3_sets()[:args.max_sets or None]
    acc: dict[str, list[float]] = {}
    n_fit = n_d = nnz = 0

    def add(k, w, c):
        a = acc.setdefault(k, [0.0, 0.0])
        a[0] += w
        a[1] += c

    # compile the kernels on a small real set first
    warm = None
    for name in sets:
        con = lib.duck()
        lib.register_eval_views(con, name)
        tr = con.execute("SELECT * FROM eval_truth").to_arrow_table().to_pylist()
        day = min(t["start_ts"] for t in tr).astimezone(_dt.timezone.utc).date()
        fdays = bl._fit_days(con, day, args.fit_days)
        r, w, c = _clock(se.load_retinas, con, fdays + [day], 5)
        con.close()
        add("load", w, c)
        is_d = r["dt"] == np.datetime64(day)
        fit, dd = se._rows(r, np.flatnonzero(~is_d)), se._rows(r, np.flatnonzero(is_d))
        if warm is None:
            sub = se._rows(r, np.arange(min(64, len(r["pkts"]))))
            w0 = stdp.init_prototypes(*sub, k=8, seed=0)
            stdp.novelty(*sub, stdp.train(*sub, w0, epochs=1))
            warm = True
        n_fit += len(fit[0]) - 1
        n_d += len(dd[0]) - 1
        nnz += len(fit[1]) + len(dd[1])
        w0, w, c = _clock(stdp.init_prototypes, *fit, k=stdp.K, seed=args.seed)
        add("stdp_init", w, c)
        wt, w, c = _clock(stdp.train, *fit, w0, eta=stdp.ETA,
                          epochs=stdp.EPOCHS, seed=args.seed)
        add("stdp_train", w, c)
        _, w, c = _clock(stdp.novelty, *dd, wt)
        add("stdp_score", w, c)
        mk = lambda x: sps.csr_matrix((x[2], x[1], x[0]),
                                      shape=(len(x[0]) - 1, stdp.N_BINS))
        xf, xd = mk(fit), mk(dd)
        km, w, c = _clock(MiniBatchKMeans(n_clusters=min(stdp.K, xf.shape[0]),
                                          random_state=args.seed,
                                          batch_size=4096, n_init=3).fit, xf)
        add("kmeans_fit", w, c)

        def km_score():
            cc = km.cluster_centers_
            cc = cc / np.maximum(np.linalg.norm(cc, axis=1, keepdims=True), 1e-12)
            return 1.0 - np.asarray((xd @ cc.T).max(axis=1)).ravel()
        _, w, c = _clock(km_score)
        add("kmeans_score", w, c)
        print(f"[efficiency] stdp {name}", file=sys.stderr)
    rows = [_row(P, "all", "fit_retinas", n_fit), _row(P, "all", "scored_retinas", n_d),
            _row(P, "all", "nnz", nnz)]
    md = [f"- {len(sets)} sets: {n_fit:,} fit source-day retinas "
          f"(trained {stdp.EPOCHS} epochs), {n_d:,} scored retinas, "
          f"{nnz:,} non-zero port buckets; K = {stdp.K}, {stdp.N_BINS} "
          "buckets; one thread", "",
          "Training cost is for each fit retina and epoch. k-means uses "
          "`n_init=3`, as in bench/stdp_eval.", "",
          "| step | wall s | CPU s | CPU µs per retina |",
          "| --- | ---: | ---: | ---: |"]
    for k, (w, c) in acc.items():
        n = (n_fit * (stdp.EPOCHS if k == "stdp_train" else 1)
             if k in ("stdp_init", "stdp_train", "kmeans_fit") else
             n_d if k.endswith("score") else n_fit + n_d)
        md.append(f"| {k} | {w:.1f} | {c:.1f} | {c / max(n, 1) * 1e6:.1f} |")
        rows += [_row(P, k, "wall_s", w), _row(P, k, "cpu_s", c)]
    proto = stdp.K * stdp.N_BINS * 8
    md += ["", f"Model state: both detectors keep {stdp.K} x {stdp.N_BINS} "
           f"float64 prototypes ({proto:,} bytes). STDP also keeps {stdp.K} "
           "thresholds."]
    rows.append(_row(P, "stdp", "state_bytes", proto + stdp.K * 8))
    rows.append(_row(P, "kmeans", "state_bytes", proto))
    _write(P, rows, md)


# ---------------------------------------------------------------- hdc

def _hdc_chunk(chains: list[str], seed: int, dim: int) -> dict:
    enc = hdc.HDCEncoder(seed, dim)
    if not getattr(_hdc_chunk, "warm", False):
        enc.encode(chains[:16])
        hdc.rff_encode(chains[:16], seed, dim)
        _hdc_chunk.warm = True
    _, hw, hc = _clock(enc.encode, chains)

    def rff():
        v = hdc.rff_encode(chains, seed, dim)
        v /= np.maximum(np.linalg.norm(v, axis=1, keepdims=True), 1e-12)
        return v
    _, rw, rc = _clock(rff)
    seen: dict[str, int] = {}

    def strings():
        for ch in chains:
            seen[ch] = seen.get(ch, 0) + 1
    _, sw, sc = _clock(strings)
    return {"n": len(chains), "tokens": sum(ch.count(",") + 1 for ch in chains),
            "hdc": (hw, hc), "rff": (rw, rc), "string": (sw, sc)}


@njit(cache=True)
def _hamming_max(q, m):
    """Best (lowest) Hamming distance of each packed row of q against m."""
    nq, nw = q.shape
    best = np.full(nq, 1 << 62, dtype=np.int64)
    arg = np.zeros(nq, dtype=np.int64)
    c1 = np.uint64(0x5555555555555555)
    c2 = np.uint64(0x3333333333333333)
    c4 = np.uint64(0x0F0F0F0F0F0F0F0F)
    h01 = np.uint64(0x0101010101010101)
    for i in range(nq):
        for j in range(m.shape[0]):
            d = 0
            for w in range(nw):
                x = q[i, w] ^ m[j, w]
                x = x - ((x >> np.uint64(1)) & c1)
                x = (x & c2) + ((x >> np.uint64(2)) & c2)
                x = (x + (x >> np.uint64(4))) & c4
                d += np.int64((x * h01) >> np.uint64(56))
            if d < best[i]:
                best[i] = d
                arg[i] = j
    return best, arg


def _pack(v: np.ndarray) -> np.ndarray:
    return np.packbits(v > 0, axis=1).view(np.uint64)


def part_hdc(args) -> None:
    P = "hdc"
    dim = hdc.D_DEFAULT
    path = lib.REPORTS / "chainfp" / "chainfp_timed.parquet"
    chains = pq.read_table(path, columns=["chain"])["chain"].to_pylist()
    chains = sorted(set(c for c in chains if c))
    if args.max_chains:
        chains = chains[:args.max_chains]
    chunks = [chains[a:a + CHAIN_CHUNK] for a in range(0, len(chains), CHAIN_CHUNK)]
    t0 = time.time()
    res = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for i, r in enumerate(pool.map(_hdc_chunk, chunks,
                                       [args.seed] * len(chunks),
                                       [dim] * len(chunks))):
            res.append(r)
            if (i + 1) % 20 == 0:
                print(f"[efficiency] hdc {i + 1}/{len(chunks)} "
                      f"{time.time() - t0:.0f}s", file=sys.stderr)
    n = sum(r["n"] for r in res)
    tok = sum(r["tokens"] for r in res)
    rows = [_row(P, "all", "chains", n), _row(P, "all", "tokens", tok)]
    md = [f"- {n:,} distinct timed chains of chainfp_timed.parquet, "
          f"{tok:,} tokens; D = {dim}; one thread per process, "
          f"{args.workers} processes", "",
          "## Encoding (all chains)", "",
          "`string` is the exact-chain count of `string_rarity`.", "",
          "| encoder | wall s | CPU s | CPU µs per chain | bytes per vector |",
          "| --- | ---: | ---: | ---: | ---: |"]
    size = {"hdc": dim, "rff": 4 * dim, "string": 0}
    for k in ("hdc", "rff", "string"):
        w = sum(r[k][0] for r in res)
        c = sum(r[k][1] for r in res)
        md.append(f"| {k} | {w:.1f} | {c:.1f} | {c / n * 1e6:.2f} | "
                  f"{size[k] or 'the chain string'} |")
        rows += [_row(P, k, "wall_s", w), _row(P, k, "cpu_s", c)]
    md.append(f"| hdc as packed bits | | | | {dim // 8} |")

    # 1-NN search on a real sample: memory M, queries Q (other chains)
    rng = np.random.default_rng(args.seed)
    pick = rng.choice(len(chains), size=min(len(chains), args.search_mem +
                                            args.search_q), replace=False)
    mem_c = [chains[i] for i in pick[:args.search_mem]]
    q_c = [chains[i] for i in pick[args.search_mem:]]
    enc = hdc.HDCEncoder(args.seed, dim)
    hm, hq = enc.encode(mem_c), enc.encode(q_c)
    rm = hdc.rff_encode(mem_c, args.seed, dim)
    rq = hdc.rff_encode(q_c, args.seed, dim)
    pm, pq_ = _pack(hm), _pack(hq)
    _hamming_max(pq_[:2], pm[:2])
    (fb, fa), fw, fc = _clock(hdc.max_sim, hq, hm)
    (hb, ha), bw, bc = _clock(_hamming_max, pq_, pm)
    _, rw, rc = _clock(hdc.max_sim, rq, rm)
    cos_bits = 1.0 - 2.0 * hb / dim
    diff = float(np.abs(cos_bits - fb).max())
    pairs = len(q_c) * len(mem_c)
    md += ["", "## 1-NN search", "",
           f"{len(q_c):,} query chains against {len(mem_c):,} memory chains "
           f"({pairs:,} pairs). The packed-bit search gives the same cosine "
           f"as the float32 search of the same hdc vectors (largest "
           f"difference {diff:.1e}, same best row for "
           f"{(ha == fa).mean():.1%} of queries; the other rows are ties).", "",
           "| search | wall s | CPU s | CPU ns per pair | memory bytes |",
           "| --- | ---: | ---: | ---: | ---: |"]
    for k, w, c, b in (("hdc, float32 product", fw, fc, hm.nbytes),
                       ("hdc, packed bits", bw, bc, pm.nbytes),
                       ("rff, float32 product", rw, rc, rm.nbytes)):
        md.append(f"| {k} | {w:.1f} | {c:.1f} | {c / pairs * 1e9:.2f} | {b:,} |")
        rows += [_row(P, "search " + k, "cpu_s", c),
                 _row(P, "search " + k, "memory_bytes", b)]
    rows.append(_row(P, "search", "pairs", pairs))
    rows.append(_row(P, "search", "bits_float_max_diff", diff))
    _write(P, rows, md)


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--part", nargs="+", choices=PARTS, default=list(PARTS))
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--min-pkts", type=int, default=20)
    ap.add_argument("--fit-days", type=int, default=28)
    ap.add_argument("--source-k", type=int, nargs="+", default=[10, 50, 100])
    ap.add_argument("--search-mem", type=int, default=100_000)
    ap.add_argument("--search-q", type=int, default=2_000)
    ap.add_argument("--max-days", type=int, default=0,
                    help="first N days only (0 = all; arrival: calendar days)")
    ap.add_argument("--max-sets", type=int, default=0,
                    help="first N p3t_* sets only (0 = all)")
    ap.add_argument("--max-chains", type=int, default=0,
                    help="first N distinct chains only (0 = all)")
    ap.add_argument("--seed", type=int, default=20261025)
    args = ap.parse_args()
    for p in args.part:
        t0 = time.time()
        {"arrival": part_arrival, "lif": part_lif, "latency": part_latency,
         "stdp": part_stdp, "hdc": part_hdc}[p](args)
        print(f"[efficiency] part {p} done in {time.time() - t0:.0f}s",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

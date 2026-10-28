#!/usr/bin/env python3
"""
bench/lif_eval — Phase 3 exit gate: per-source LIF / ALIF timing detectors.

Neuromorphic plan Phase 3 (docs/ARCHITECTURE.md §9.1).  Scores every source
with >= ``--min-pkts`` unmasked packets on the injected day D of one
``adversarysim --inject`` set, with the population, truth and recall@k
arithmetic of ``bench/baselines.py``:

  lif            primary: sg.lif bank (24 neurons, tau 1 ms .. 1 day),
                 bands set by the source's median IAT, ALIF adaptive
                 thresholds; score = max of the two readouts (change,
                 regularity), each calibrated against the fit window
  lif_change     the calibrated change readout only
  lif_reg        the calibrated regularity readout only
  lif_nocal      lif, each readout ranked inside D (no fit window)
  untrained_lif  untrained copy (rule 7 of §9.3): 24 random taus
                 (log-uniform 10 ms .. 10 days), every neuron, no
                 adaptation, ranked inside D
  hawkes         classical twin: exponential Hawkes (the same kernel) fit
                 per source by EM, time-rescaling KS sqrt(n) * D,
                 calibrated against the fit window
  hawkes_nocal   hawkes ranked inside D
  pacing         baseline (the pacing module's statistics): max of
                 -log CV(IAT) and |log(median IAT of the 2nd half / 1st
                 half)|, ranked inside D
  pacing_cal     pacing with the lif calibration
  pacing_robust  round 2 twin: -log(MAD / median) of the IATs (one long gap
                 does not change it) and the same half split, ranked inside D
  pacing_robust_cal   pacing_robust with the lif calibration
  periodogram    round 2 Lomb-Scargle twin: the classical periodogram of the
                 evenly binned packet times (bin = median IAT / 4, at most
                 32,768 bins), the largest peak / mean power over the full
                 span and over 6 h windows (50 % overlap); for evenly spaced
                 samples Lomb-Scargle is this periodogram.  Ranked inside D
  burst_fano     round 2 burst twin of untrained_lif: the largest
                 log(Fano factor) of the packet counts at the 24 time scales
                 of the LIF bank (1 ms .. 1 day).  Ranked inside D
  burst_b        Goh-Barabasi burstiness (sd - mean) / (sd + mean) of the
                 IATs.  Ranked inside D
  *_cal          each round 2 twin with the lif calibration
  pkt_count, random   sanity rows

Calibration: the fit window is the ``--fit-days`` (28) recorded days
before D.  Each readout of D is turned into -log10 of its exceedance rate
among the fit-window source-days in the same packet-count decile, with an
exponential peaks-over-threshold tail above the decile's 90th percentile.  "Ranked inside D"
uses the same formula with D's own sources as the reference.  A detector
with two readouts takes the larger.

Gate (§9.1): lif beats pacing and untrained_lif on jittered_beacon and
rhythm_change (pooled recall@k over every set).

Output: output/reports/lif_eval/lif_eval_<NAME>.{parquet,md}
``--summary NAME [NAME ...]`` pools saved sets (and their baselines_<NAME>
source rows) into lif_eval_summary.{parquet,md}.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
import time
from pathlib import Path

import math

import numpy as np
from numba import njit
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib, lif
from bench import arrival_series as ars
from bench import baselines as bl

OUT = lib.REPORTS / "lif_eval"
DETECTORS = ("lif", "lif_change", "lif_reg", "lif_nocal", "untrained_lif",
             "hawkes", "hawkes_nocal", "pacing", "pacing_cal", "pacing_robust",
             "pacing_robust_cal", "pkt_count", "random")
TWINS_ONLY = ("pacing_robust", "pacing_robust_cal", "periodogram",
              "periodogram_cal", "burst_fano", "burst_fano_cal", "burst_b",
              "burst_b_cal")
PG_MAX_BINS = 32768
PG_WINDOW_S = 6 * 3600
GATE_ARCH = ("jittered_beacon", "rhythm_change")
GATE_RIVALS = ("pacing", "untrained_lif")
TAIL_Q = 0.9          # lif.calibrate(): start of the exponential tail

SUMMARY_SCHEMA = pa.schema([
    ("detector",   pa.string()),
    ("archetype",  pa.string()),
    ("is_control", pa.bool_()),
    ("k",          pa.uint32()),
    ("n_sets",     pa.uint32()),
    ("n_truth",    pa.uint32()),
    ("hits",       pa.uint32()),
    ("recall",     pa.float64()),
    ("chance",     pa.float64()),
])


# ---------------------------------------------------------------- data

def load_day(con, day: _dt.date, min_pkts: int, mask_ends: np.ndarray) -> dict:
    """Spike trains of the sources with >= min_pkts unmasked packets."""
    tab = con.execute(f"""
        WITH p AS (
            SELECT src_ip, epoch_us(ts) AS t FROM packets
            WHERE dt = DATE '{day}' AND {ars.NOT_NTP}
              AND {lib.mask_predicate('ts')}
        ), c AS (
            SELECT src_ip FROM p GROUP BY src_ip HAVING count(*) >= {min_pkts}
        )
        SELECT src_ip, t FROM p SEMI JOIN c USING (src_ip)
        ORDER BY src_ip, t
    """).to_arrow_table()
    ip_col = tab["src_ip"].combine_chunks().dictionary_encode()
    ips = ip_col.dictionary.to_pylist()
    idx = ip_col.indices.to_numpy()
    t = tab["t"].to_numpy() / 1e6
    if not len(idx):
        return {"ips": [], "t": t, "seg": np.zeros(0, dtype=np.int64),
                "starts": np.zeros(1, dtype=np.int64),
                "n": np.zeros(0, dtype=np.int64)}
    starts = np.flatnonzero(np.r_[True, idx[1:] != idx[:-1], True])
    order = idx[starts[:-1]]
    seg = np.searchsorted(mask_ends, t, side="right")
    return {"ips": [ips[i] for i in order], "t": t, "seg": seg,
            "starts": starts, "n": np.diff(starts)}


def readouts(d: dict, untrained_taus: np.ndarray) -> dict:
    t, seg, st = d["t"], d["seg"], d["starts"]
    med = lif.median_iat(t, seg, st)
    ch, rg = lif.bank_scores(t, seg, st, med)
    uch, urg = lif.bank_scores(t, seg, st, med, taus=untrained_taus,
                               band=(0.0, np.inf), change_band=(0.0, np.inf),
                               adapt=False)
    ks, br = lif.hawkes_scores(t, seg, st, med)
    cv, split, rcv = _pacing(t, seg, st)
    fin = lambda x: np.where(np.isfinite(x), x, -1e9)
    return {"change": ch, "reg": fin(rg), "u_change": uch, "u_reg": fin(urg),
            "ks": ks, "branching": br, "cv": cv, "split": split, "rcv": rcv,
            "logn": np.log(d["n"]), "med_iat": med}


def pacing_readouts(d: dict) -> dict:
    """The classical twin readouts only (--twins-only)."""
    t, seg, st = d["t"], d["seg"], d["starts"]
    cv, split, rcv = _pacing(t, seg, st)
    fano, bb = _burst(t, st, lif.TAUS)
    return {"cv": cv, "split": split, "rcv": rcv,
            "pg": _periodogram(t, st, lif.median_iat(t, seg, st)),
            "fano": fano, "bb": bb, "logn": np.log(d["n"])}


def _peak_ratio(c: np.ndarray, lo: int) -> float:
    """Largest periodogram power / mean power, frequency bins >= lo."""
    c = c - c.mean()
    p = np.abs(np.fft.rfft(c)) ** 2
    p = p[lo:]
    return float(p.max() / p.mean()) if len(p) > 1 and p.mean() > 0 else 0.0


def _periodogram(t, starts, med) -> np.ndarray:
    S = len(starts) - 1
    out = np.zeros(S)
    for s in range(S):
        tt = t[starts[s]:starts[s + 1]]
        span = tt[-1] - tt[0]
        if len(tt) < 8 or span <= 0:
            continue
        b = max(med[s] / 4, span / PG_MAX_BINS, 1e-3)
        c = np.bincount(((tt - tt[0]) / b).astype(np.int64)).astype(float)
        best = _peak_ratio(c, 3)            # periods < span / 3
        w = int(PG_WINDOW_S / b)
        if w >= 16 and len(c) > w:
            for a in range(0, len(c) - w + 1, w // 2):
                seg = c[a:a + w]
                if seg.sum() >= 8:
                    best = max(best, _peak_ratio(seg, 3))
        out[s] = np.log(best) if best > 0 else 0.0
    return out


@njit(cache=True)
def _burst(t, starts, taus):
    """Largest log Fano factor over the scales, and the Goh-Barabasi B."""
    S = len(starts) - 1
    fano = np.zeros(S)
    bb = np.zeros(S)
    for s in range(S):
        a, b = starts[s], starts[s + 1]
        n = b - a
        if n < 8:
            continue
        span = t[b - 1] - t[a]
        best = 0.0
        for tau in taus:
            nb = max(1.0, math.ceil(span / tau))
            if nb < 2:
                continue
            s2, run, last = 0.0, 0, -1
            for i in range(a, b):
                k = int((t[i] - t[a]) / tau)
                if k == last:
                    run += 1
                else:
                    s2 += run * run
                    run, last = 1, k
            s2 += run * run
            m = n / nb
            v = s2 / nb - m * m
            if m > 0 and v > 0:
                best = max(best, math.log(v / m))
        fano[s] = best
        mu, q = 0.0, 0.0
        for i in range(a + 1, b):
            d = t[i] - t[i - 1]
            mu += d
            q += d * d
        mu /= n - 1
        sd = math.sqrt(max(q / (n - 1) - mu * mu, 0.0))
        bb[s] = (sd - mu) / (sd + mu) if sd + mu > 0 else 0.0
    return fano, bb


def _pacing(t, seg, starts) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    S = len(starts) - 1
    cv = np.zeros(S)
    split = np.zeros(S)
    rcv = np.zeros(S)
    for s in range(S):
        a, b = starts[s], starts[s + 1]
        tt, gg = t[a:b], seg[a:b]
        dd = np.diff(tt)[gg[1:] == gg[:-1]]
        if len(dd) < 4:
            continue
        m = dd.mean()
        cv[s] = -np.log(max(dd.std() / m, 1e-6)) if m > 0 else 0.0
        md = np.median(dd)
        if md > 0:
            rcv[s] = -np.log(max(np.median(np.abs(dd - md)) / md, 1e-6))
        h = len(dd) // 2
        m1, m2 = np.median(dd[:h]), np.median(dd[h:])
        split[s] = abs(np.log(max(m2, 1e-3) / max(m1, 1e-3)))
    return cv, split, rcv


# ---------------------------------------------------------------- scores

def detector_scores(dr: dict, fit: dict, seed: int) -> dict:
    cal = lambda k: lif.calibrate(dr[k], dr["logn"], fit[k], fit["logn"])
    own = lambda k: lif.calibrate(dr[k], dr["logn"], dr[k], dr["logn"], n_bins=1)
    rng = np.random.default_rng(seed)
    out = {"lif_change": cal("change"), "lif_reg": cal("reg")}
    out["lif"] = np.maximum(out["lif_change"], out["lif_reg"])
    out["lif_nocal"] = np.maximum(own("change"), own("reg"))
    out["untrained_lif"] = np.maximum(own("u_change"), own("u_reg"))
    out["hawkes"] = cal("ks")
    out["hawkes_nocal"] = own("ks")
    out["pacing"] = np.maximum(own("cv"), own("split"))
    out["pacing_cal"] = np.maximum(cal("cv"), cal("split"))
    out["pacing_robust"] = np.maximum(own("rcv"), own("split"))
    out["pacing_robust_cal"] = np.maximum(cal("rcv"), cal("split"))
    out["pkt_count"] = dr["logn"]
    out["random"] = rng.random(len(dr["logn"]))
    return {k: out[k] for k in DETECTORS}


# ---------------------------------------------------------------- metrics

def eval_clean(name: str, ips: list[str], scores: dict, truth: list[dict],
               ks: list[int], seed: int) -> list[dict]:
    """bl.eval_source, but each archetype is ranked among the recorded
    sources plus its own sources only.  Otherwise the other injected
    archetypes (40 distributed_brute sources at exact 60 s ticks, for
    example) take alert slots, and the recall of one archetype depends on
    which others are in the set."""
    injected = {t["src_ip"] for t in truth if t["level"] == "source"}
    real = np.array([ip not in injected for ip in ips])
    pos = {ip: i for i, ip in enumerate(ips)}
    groups: dict[tuple, list[int]] = {}
    for t in truth:
        if t["level"] == "source" and t["src_ip"] in pos:
            groups.setdefault((t["archetype"], t["is_control"]), []).append(
                pos[t["src_ip"]])
    out = []
    for (arch, ctrl), idx in groups.items():
        pop = np.flatnonzero(real)
        pop = np.concatenate([pop, np.array(idx)])
        for det, s in scores.items():
            r = bl.ranks_desc(np.asarray(s, dtype=float)[pop], seed)
            rk = r[-len(idx):]
            for k in ks:
                hits = int((rk <= k).sum())
                out.append({
                    "eval_name": name, "level": "source_lif", "detector": det,
                    "archetype": arch, "is_control": ctrl,
                    "n_truth": len(idx), "k": k, "hits": hits,
                    "recall": hits / len(idx), "chance": min(1.0, k / len(pop)),
                    "median_rank": float(np.median(rk)), "ttd_s": None,
                })
    return out


# ---------------------------------------------------------------- reports

def _table(rows: list[dict], ks: list[int], dets: list[str]) -> list[str]:
    md = []
    for k in ks:
        sub = [r for r in rows if r["k"] == k]
        md += [f"### k = {k}", "",
               "| archetype | n | chance | " + " | ".join(dets) + " |",
               "| --- | ---: | ---: | " + " | ".join("---:" for _ in dets) + " |"]
        keys = list(dict.fromkeys((r["archetype"], r["is_control"]) for r in sub))
        for arch, ctrl in keys:
            cells = {r["detector"]: r for r in sub
                     if r["archetype"] == arch and r["is_control"] == ctrl}
            any_r = next(iter(cells.values()))
            md.append(f"| {arch}{' (control)' if ctrl else ''} | "
                      f"{any_r['n_truth']} | {any_r['chance']:.3f} | " +
                      " | ".join(f"{cells[d]['recall']:.2f}" if d in cells
                                 else "" for d in dets) + " |")
        md.append("")
    return md


def run(args: argparse.Namespace) -> None:
    t0 = time.time()
    con = lib.duck()
    lib.register_eval_views(con, args.eval)
    truth = con.execute("SELECT * FROM eval_truth").to_arrow_table().to_pylist()
    day = min(t["start_ts"] for t in truth).astimezone(_dt.timezone.utc).date()
    fit_days = bl._fit_days(con, day, args.fit_days)
    mask_ends = np.array(sorted(e.timestamp() for _, e, _ in
                                lib.load_sensor_mask()))
    # the same tau range as the trained bank (round 2 correction D12; the
    # first round drew 10 ms .. 10 days)
    utaus = np.sort(np.exp(np.random.default_rng(args.seed).uniform(
        np.log(lif.TAUS[0]), np.log(lif.TAUS[-1]), len(lif.TAUS))))
    ro = pacing_readouts if args.twins_only else (lambda x: readouts(x, utaus))
    fit_parts = []
    for fd in fit_days:
        dd = load_day(con, fd, args.min_pkts, mask_ends)
        if len(dd["ips"]):
            fit_parts.append(ro(dd))
    fit = {k: np.concatenate([p[k] for p in fit_parts]) for k in fit_parts[0]} \
        if fit_parts else None
    d = load_day(con, day, args.min_pkts, mask_ends)
    con.close()
    if fit is None or not len(d["ips"]):
        raise SystemExit(f"[lif_eval] no sources on {day} or its fit window")
    if args.twins_only:
        return _twins_only(args, day, d, fit, truth, t0)
    dr = readouts(d, utaus)
    scores = detector_scores(dr, fit, args.seed)
    rows = eval_clean(args.eval, d["ips"], scores, truth, args.source_k,
                      args.seed)
    from bench import harness2
    harness2.write_ranks("lif_eval", args.eval, harness2.truth_ranks(
        args.eval, day, d["ips"], scores, truth, args.seed))
    dets = list(scores)
    base = lib.REPORTS / "baselines" / f"baselines_{args.eval}.parquet"
    brows = ([r for r in pq.read_table(base).to_pylist() if r["level"] == "source"]
             if base.exists() else [])
    in_pop = {t["src_ip"] for t in truth if t["src_ip"] in set(d["ips"])}
    md = [f"- injection set: `{args.eval}`, scored day {day}",
          f"- fit window: {fit_days[0]} .. {fit_days[-1]} ({len(fit_days)} "
          f"recorded days, {len(fit['logn']):,} source-days, sensormask "
          "applied)",
          f"- scored: {len(d['ips']):,} sources with >= {args.min_pkts} "
          f"unmasked packets; truth sources in this population: {len(in_pop)}",
          f"- run time: {time.time() - t0:.0f} s", "",
          "Recall at a fixed alert budget, no point adjustment. Each "
          f"archetype is ranked among the recorded sources with >= "
          f"{args.min_pkts} packets plus its own sources.", "",
          "## LIF detectors and twins", ""]
    md += _table(rows, args.source_k, dets)
    if brows:
        md += ["## baselines.py on the same set (all sources of D)", ""]
        md += _table(brows, args.source_k,
                     list(dict.fromkeys(r["detector"] for r in brows)))
    paths = lib.Report(name="lif_eval", rows=rows, schema=bl.RESULT_SCHEMA,
                       markdown="\n".join(md) + "\n").write(suffix=args.eval)
    print(f"[lif_eval] wrote {paths['parquet']} ({time.time() - t0:.0f}s)",
          file=sys.stderr)


def summary(names: list[str]) -> None:
    """Pool recall over sets: sum(hits) / sum(n_truth) per detector."""
    rows = []
    for n in names:
        rows += pq.read_table(OUT / f"lif_eval_{n}.parquet").to_pylist()
        b = lib.REPORTS / "baselines" / f"baselines_{n}.parquet"
        if b.exists():
            # baselines.py ranks every source of D: keep its rows apart
            rows += [{**r, "detector": "bl_" + r["detector"]}
                     for r in pq.read_table(b).to_pylist()
                     if r["level"] == "source"]
    agg: dict[tuple, dict] = {}
    for r in rows:
        key = (r["detector"], r["archetype"], r["is_control"], r["k"])
        a = agg.setdefault(key, {"sets": set(), "n_truth": 0, "hits": 0,
                                 "chance_w": 0.0})
        a["sets"].add(r["eval_name"])
        a["n_truth"] += r["n_truth"]
        a["hits"] += r["hits"]
        a["chance_w"] += r["chance"] * r["n_truth"]
    out = [{"detector": k[0], "archetype": k[1], "is_control": k[2], "k": k[3],
            "n_sets": len(a["sets"]), "n_truth": a["n_truth"],
            "hits": a["hits"], "recall": a["hits"] / max(1, a["n_truth"]),
            "chance": a["chance_w"] / max(1, a["n_truth"])}
           for k, a in agg.items()]
    ks = sorted({r["k"] for r in out if r["detector"] in DETECTORS})
    lif_dets = [d for d in DETECTORS if any(r["detector"] == d for r in out)]
    base_dets = [d for d in dict.fromkeys(r["detector"] for r in out)
                 if d not in DETECTORS]
    rec = {(r["detector"], r["archetype"], r["k"]): r["recall"] for r in out
           if not r["is_control"]}
    md = [f"- sets: {len(names)} ({', '.join(names)})", "",
          "## Gate (ARCHITECTURE §9.1, Phase 3)", "",
          "For each archetype and rival: `lif` has a pooled recall equal "
          "to or higher than the rival at each k, and a higher sum of "
          "recall over the k values. (When both detectors find every "
          "source at a k, that k cannot show a difference.)", "",
          "| archetype | rival | lif (sum) | rival (sum) | result |",
          "| --- | --- | ---: | ---: | --- |"]
    passed = True
    for a in GATE_ARCH:
        for rv in GATE_RIVALS:
            lv = [rec.get(("lif", a, k), 0.0) for k in ks]
            rvv = [rec.get((rv, a, k), 0.0) for k in ks]
            ok = all(x >= y for x, y in zip(lv, rvv)) and sum(lv) > sum(rvv)
            passed &= ok
            md.append(f"| {a} | {rv} | {sum(lv):.2f} | {sum(rvv):.2f} | "
                      f"{'pass' if ok else 'failure'} |")
    md += ["", f"**Gate: {'pass' if passed else 'failure'}**"]
    md += ["", "## Pooled recall: LIF detectors and twins "
           "(sources with the minimum packet count)", ""]
    md += _table([r for r in out if r["detector"] in lif_dets], ks, lif_dets)
    if base_dets:
        md += ["## Pooled recall: baselines.py (all sources of D)", ""]
        bks = sorted({r["k"] for r in out if r["detector"] in base_dets})
        md += _table([r for r in out if r["detector"] in base_dets], bks,
                     base_dets)
    paths = lib.Report(name="lif_eval", rows=out, schema=SUMMARY_SCHEMA,
                       markdown="\n".join(md) + "\n").write(suffix="summary")
    print(f"[lif_eval] wrote {paths['markdown']}", file=sys.stderr)


def _twins_only(args, day, d, fit, truth, t0) -> None:
    """Add the TWINS_ONLY rank rows to a saved set's harness2 ranks."""
    from bench import harness2
    dr = pacing_readouts(d)
    cal = lambda k: lif.calibrate(dr[k], dr["logn"], fit[k], fit["logn"])
    own = lambda k: lif.calibrate(dr[k], dr["logn"], dr[k], dr["logn"], n_bins=1)
    scores = {"pacing_robust": np.maximum(own("rcv"), own("split")),
              "pacing_robust_cal": np.maximum(cal("rcv"), cal("split"))}
    for name, k in (("periodogram", "pg"), ("burst_fano", "fano"),
                    ("burst_b", "bb")):
        scores[name], scores[name + "_cal"] = own(k), cal(k)
    new = harness2.truth_ranks(args.eval, day, d["ips"], scores, truth, args.seed)
    path = harness2.OUT / "lif_eval" / f"{args.eval}_ranks.parquet"
    old = [r for r in pq.read_table(path).to_pylist()
           if r["detector"] not in TWINS_ONLY] if path.exists() else []
    harness2.write_ranks("lif_eval", args.eval, old + new)
    print(f"[lif_eval] {args.eval}: added {', '.join(TWINS_ONLY)} ranks "
          f"({time.time() - t0:.0f}s)", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--eval", metavar="NAME",
                   help="adversarysim --inject set to score.")
    g.add_argument("--summary", nargs="+", metavar="NAME",
                   help="pool these saved sets into lif_eval_summary")
    ap.add_argument("--fit-days", type=int, default=28)
    ap.add_argument("--min-pkts", type=int, default=20)
    ap.add_argument("--source-k", type=int, nargs="+", default=[10, 50, 100])
    ap.add_argument("--seed", type=int, default=20261024)
    ap.add_argument("--twins-only", action="store_true",
                    help="with --eval: compute only the pacing_robust twins "
                         "and add their ranks to the saved harness2 ranks")
    args = ap.parse_args()
    if args.summary:
        summary(args.summary)
    else:
        run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
bench/phase4_gate — Phase 4 gate with the tool-made escalation labels.

docs/NEUROMORPHIC_ROUND2_PLAN.md §3.4.  For each score day D (one each
``--every`` recorded days of the test period, with D + horizon inside the
corpus):

  candidates  sources with a neuro source-day (>= 20 unmasked packets) in
              the ``--window`` days up to D that have an escalation label
              (bench/priority_labels.escalation: no level-1 evidence on or
              before D)
  flagged     the neuro risk term of the window is > 0.  ``--term``:
              lif        the LIF part of the capped term only (result 6):
                         best calibrated readout > NEURO_FLAG + log10(days)
              capped     compute_risk_score.neuro_score (LIF + HDC parts)
              surprisal  compute_risk_score.neuro_surprisal (proposal C1;
                         its matched twin is ``capped``)
              ``--calibration`` count | context selects the *_cal or the
              *_ctx day columns of the neuro stage (proposal A1)
  nocal       the same number of sources, chosen by the uncalibrated
              readouts (rank of max(change, reg) among the candidates);
              the co-primary of round 2 correction D14
  control     candidates that are not flagged, re-weighted to the flagged
              sources' strata (packet-count decile x active-day bucket):
              the escalation rate a source with the same activity has

The gate (plan §3.4) needs the flagged escalation rate above the control
rate; the intervals are a cluster bootstrap over score days.

Output: output/reports/phase4_gate/phase4_gate.{parquet,md}
"""
from __future__ import annotations

import argparse
import datetime as _dt
import math
import sys
import time
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib
from bench import harness2
from bench import priority_labels as pl
from risk import compute_risk_score as crs
from risk.compute_risk_score import NEURO_FLAG

OUT = lib.REPORTS / "phase4_gate"
SCHEMA = pa.schema([
    ("score_day", pa.date32()), ("group", pa.string()),
    ("n", pa.uint32()), ("escalated", pa.float64()),
])


def _term_flags(term, u, ndays, ips, cch, crg, d, window, hdays, hip, hpr,
                hdr, n_pop) -> np.ndarray:
    """neuro risk term > 0 for each source of ``u``, with the window's LIF
    and HDC source-days in the form of the features table."""
    pos = {s: i for i, s in enumerate(u)}
    mch = np.zeros(len(u))
    mrg = np.zeros(len(u))
    for s, a, b in zip(ips, cch, crg):
        i = pos.get(s)
        if i is not None:
            mch[i], mrg[i] = max(mch[i], a), max(mrg[i], b)
    hsel = (hdays > d - np.timedelta64(window, "D")) & (hdays <= d)
    hn, hp, hq = np.zeros(len(u)), np.zeros(len(u)), np.zeros(len(u))
    for s, a, b in zip(hip[hsel], hpr[hsel], hdr[hsel]):
        i = pos.get(s)
        if i is not None:
            hn[i] += 1
            hp[i], hq[i] = max(hp[i], a), max(hq[i], b)
    out = np.zeros(len(u), dtype=bool)
    for i in range(len(u)):
        r = {"neuro_days": int(ndays[i]), "neuro_change": mch[i],
             "neuro_reg": mrg[i], "neuro_arrival_min": 0,
             "neuro_hdc_days": int(hn[i]), "neuro_hdc_proto": hp[i],
             "neuro_hdc_drift": hq[i]}
        v = (crs.neuro_surprisal(r, n_pop)[0] if term == "surprisal"
             else crs.neuro_score(r)[0])
        out[i] = v > 0
    return out


def run(args) -> None:
    t0 = time.time()
    labels = pl.load()
    sfx = "ctx" if args.calibration == "context" else "cal"
    con = lib.duck()
    nd = con.execute(f"""
        SELECT src_ip, dt, n_pkts, change, reg,
               change_{sfx} AS change_cal, reg_{sfx} AS reg_cal
        FROM read_parquet('{lib.REPORTS / "neuro" / "neuro_days.parquet"}')
        WHERE dt >= DATE '{harness2.DEV_END}' - INTERVAL {args.window} DAY
        ORDER BY dt
    """).to_arrow_table()
    hd = con.execute(f"""
        SELECT src_ip, dt, proto_{sfx} AS proto, drift_{sfx} AS drift
        FROM read_parquet('{lib.REPORTS / "neuro" / "neuro_hdc_days.parquet"}')
        WHERE dt >= DATE '{harness2.DEV_END}' - INTERVAL {args.window} DAY
          AND proto_{sfx} IS NOT NULL AND NOT isnan(proto_{sfx})
    """).to_arrow_table()
    n_pop = con.execute(f"""
        SELECT count(*) FROM read_parquet('{lib.REPORTS / "neuro" / "neuro.parquet"}')
        WHERE lif_days > 0 OR hdc_days > 0
    """).fetchone()[0]
    con.close()
    hdays = np.array(hd["dt"].to_numpy(zero_copy_only=False), dtype="datetime64[D]")
    hip = np.array(hd["src_ip"].to_pylist(), dtype=object)
    hpr = np.nan_to_num(hd["proto"].to_numpy(zero_copy_only=False).astype(float))
    hdr = np.nan_to_num(hd["drift"].to_numpy(zero_copy_only=False).astype(float))
    days = np.array(nd["dt"].to_numpy(zero_copy_only=False), dtype="datetime64[D]")
    ip = np.array(nd["src_ip"].to_pylist(), dtype=object)
    npk = nd["n_pkts"].to_numpy().astype(float)
    cch = np.nan_to_num(nd["change_cal"].to_numpy(zero_copy_only=False).astype(float))
    crg = np.nan_to_num(nd["reg_cal"].to_numpy(zero_copy_only=False).astype(float))
    cal = np.maximum(cch, crg)
    raw = np.maximum(nd["change"].to_numpy(), nd["reg"].to_numpy())
    rec = np.unique(days)
    last = rec.max() - np.timedelta64(args.horizon, "D")
    sdays = [d for d in rec[rec >= np.datetime64(harness2.DEV_END)] if d <= last]
    sdays = sdays[::args.every]
    rows, per_day = [], []
    for d in sdays:
        sel = (days > d - np.timedelta64(args.window, "D")) & (days <= d)
        if not sel.any():
            continue
        esc = pl.escalation(labels, d.astype(object), args.horizon)
        # per-source aggregates over the window
        u, inv = np.unique(ip[sel], return_inverse=True)
        ndays = np.bincount(inv)
        pk = np.bincount(inv, weights=npk[sel])
        best = np.full(len(u), -np.inf)
        np.maximum.at(best, inv, cal[sel])
        braw = np.full(len(u), -np.inf)
        np.maximum.at(braw, inv, raw[sel])
        lab = np.array([esc.get(s, -1) for s in u])
        keep = lab >= 0
        u, ndays, pk, best, braw, lab = (x[keep] for x in (u, ndays, pk, best, braw, lab))
        if not len(u):
            continue
        if args.term == "lif":
            flag = best - NEURO_FLAG - np.log10(np.maximum(ndays, 1)) > 0
        else:
            flag = _term_flags(args.term, u, ndays, ip[sel], cch[sel], crg[sel],
                               d, args.window, hdays, hip, hpr, hdr, n_pop)
        nf = int(flag.sum())
        nocal = np.zeros(len(u), dtype=bool)
        if nf:
            nocal[np.argsort(-braw, kind="stable")[:nf]] = True
        dec = np.searchsorted(np.quantile(np.log(pk), np.linspace(0, 1, 11)[1:-1]),
                              np.log(pk))
        dbin = np.minimum(np.log2(ndays).astype(int), 4)
        strata = dec * 10 + dbin
        # control: unflagged, re-weighted to the flagged strata
        ctl = 0.0
        if nf:
            for s in np.unique(strata[flag]):
                c = (~flag) & (strata == s)
                w = (flag & (strata == s)).sum() / nf
                ctl += w * (lab[c].mean() if c.any() else lab[~flag].mean())
        row = {"score_day": d.astype(object), "candidates": len(u),
               "base": lab.mean(), "flagged_n": nf,
               "flagged": lab[flag].mean() if nf else np.nan,
               "flagged_hits": int(lab[flag].sum()),
               "nocal": lab[nocal].mean() if nf else np.nan,
               "nocal_hits": int(lab[nocal].sum()),
               "control": ctl if nf else np.nan}
        per_day.append(row)
        for g in ("base", "flagged", "nocal", "control"):
            rows.append({"score_day": row["score_day"], "group": g,
                         "n": nf if g != "base" else len(u),
                         "escalated": float(row[g])})
    ok = [r for r in per_day if r["flagged_n"]]
    F = np.array([r["flagged_n"] for r in ok], dtype=float)
    def pooled(key, idx):
        w = F[idx]
        v = np.array([ok[i][key] for i in idx])
        return float((v * w).sum() / w.sum())
    rng = np.random.default_rng(args.seed)
    idx_all = np.arange(len(ok))
    est = {k: pooled(k, idx_all) for k in ("flagged", "nocal", "control")}
    bs = {k: [] for k in est}
    diff = []
    for _ in range(harness2.BOOT):
        i = rng.integers(0, len(ok), len(ok))
        for k in est:
            bs[k].append(pooled(k, i))
        diff.append(bs["flagged"][-1] - bs["control"][-1])
    ci = {k: np.quantile(v, [0.025, 0.975]) for k, v in bs.items()}
    dci = np.quantile(diff, [0.025, 0.975])
    passed = dci[0] > 0
    md = [f"- {len(per_day)} score days ({sdays[0]} .. {sdays[-1]}, every "
          f"{args.every} recorded days of the test period), window "
          f"{args.window} days, horizon {args.horizon} days; run time "
          f"{time.time() - t0:.0f} s",
          f"- candidates per day (median): {int(np.median([r['candidates'] for r in per_day])):,}; "
          f"flagged per day (median): {int(np.median(F))}",
          f"- base escalation rate of all candidates: "
          f"{np.mean([r['base'] for r in per_day]):.4f}", "",
          "| group | escalation rate | 95 % interval |", "| --- | ---: | --- |"]
    md.insert(0, f"- term: `{args.term}`, calibration: `{args.calibration}`"
              + (f", surprisal level log2 {n_pop:,} sources"
                 if args.term == "surprisal" else ""))
    for k, name in (("flagged", f"`{args.term}` risk term > 0"),
                    ("nocal", "same count, uncalibrated readouts"),
                    ("control", "not flagged, same activity strata")):
        md.append(f"| {name} | {est[k]:.4f} | [{ci[k][0]:.4f}, {ci[k][1]:.4f}] |")
    md += ["", f"Difference flagged - control: {est['flagged'] - est['control']:+.4f} "
           f"[{dci[0]:+.4f}, {dci[1]:+.4f}]", "",
           f"**Gate: {'pass' if passed else 'failure'}** (the interval of the "
           "difference must be above 0)", "",
           "The classical twin (a calibrated `pacing` flag) is not in this "
           "test: the neuro cache has no pacing readouts for each source-day."]
    suffix = ("" if (args.term, args.calibration) == ("lif", "count")
              else f"{args.term}_{args.calibration}")
    paths = lib.Report(name="phase4_gate", rows=rows, schema=SCHEMA,
                       markdown="\n".join(md) + "\n").write(suffix=suffix)
    print(f"[phase4_gate] wrote {paths['markdown']}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--window", type=int, default=28)
    ap.add_argument("--horizon", type=int, default=30)
    ap.add_argument("--every", type=int, default=7)
    ap.add_argument("--seed", type=int, default=20261025)
    ap.add_argument("--term", choices=("lif", "capped", "surprisal"),
                    default="lif")
    ap.add_argument("--calibration", choices=("count", "context"),
                    default="count")
    run(ap.parse_args())
    return 0


if __name__ == "__main__":
    sys.exit(main())

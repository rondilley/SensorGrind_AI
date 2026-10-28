#!/usr/bin/env python3
"""
bench/stdp_eval — Phase 5: WTA-STDP port-retina prototypes vs their twins.

Neuromorphic plan Phase 5 (docs/ARCHITECTURE.md §9.1).  Scores every source
with >= ``--min-pkts`` unmasked packets that have a destination port on
the injected day D of one ``adversarysim --inject`` set:

  stdp            primary: sg.stdp winner-take-all network (K = 256 output
                  neurons, 4,096 port buckets), STDP + homeostasis, trained
                  on the source-days of the fit window; score = novelty
                  1 - best cosine to a learned prototype
  kmeans          classical twin: spherical mini-batch k-means with the same
                  K on the same retinas
  untrained_stdp  untrained copy (rule 7 of §9.3): the same network with
                  eta = 0 (K random fit retinas as prototypes)
  pkt_count, random   sanity rows

Each archetype is ranked among the recorded sources plus its own sources
(bench/lif_eval.eval_clean).  The baselines_<NAME> source rows
(new_port_24, iforest, ...) are pooled into the summary.

Gate (§9.1, Phase 5): stdp beats kmeans and untrained_stdp on
chain_mutation (pooled recall, the lif_eval rule: >= at each k and a
higher sum over k).

Output: output/reports/stdp_eval/stdp_eval_<NAME>.{parquet,md}
``--summary NAME [NAME ...]`` pools saved sets into stdp_eval_summary.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
import time
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib, stdp
from bench import arrival_series as ars
from bench import baselines as bl
from bench import lif_eval as le

OUT = lib.REPORTS / "stdp_eval"
DETECTORS = ("stdp", "kmeans", "untrained_stdp", "pkt_count", "random")
GATE_ARCH = ("chain_mutation",)
GATE_RIVALS = ("kmeans", "untrained_stdp")


def load_retinas(con, days: list[_dt.date], min_pkts: int) -> dict:
    """Unit-norm port retinas of every (source, day) in ``days``."""
    dl = ", ".join(f"DATE '{d}'" for d in days)
    tab = con.execute(f"""
        WITH p AS (
            SELECT src_ip, dt, dst_port FROM packets
            WHERE dt IN ({dl}) AND dst_port IS NOT NULL AND {ars.NOT_NTP}
              AND {lib.mask_predicate('ts')}
        ), c AS (
            SELECT src_ip, dt FROM p GROUP BY ALL HAVING count(*) >= {min_pkts}
        )
        SELECT src_ip, dt, dst_port, count(*) AS n
        FROM p SEMI JOIN c USING (src_ip, dt)
        GROUP BY ALL ORDER BY src_ip, dt, dst_port
    """).to_arrow_table()
    ip = tab["src_ip"].to_numpy(zero_copy_only=False)
    dt = tab["dt"].to_numpy(zero_copy_only=False)
    new = np.r_[True, (ip[1:] != ip[:-1]) | (dt[1:] != dt[:-1])]
    owner = np.cumsum(new) - 1
    first = np.flatnonzero(new)
    n_src = len(first)
    cnt = tab["n"].to_numpy()
    indptr, bins, vals = stdp.retinas(owner, tab["dst_port"].to_numpy(), cnt, n_src)
    pk = np.add.reduceat(cnt, first) if len(cnt) else cnt
    return {"ip": ip[first].tolist(), "dt": dt[first], "indptr": indptr,
            "bins": bins, "vals": vals, "pkts": pk}


def _rows(r: dict, sel: np.ndarray) -> tuple:
    """CSR rows ``sel`` of retina set ``r``."""
    ip, b, v = r["indptr"], r["bins"], r["vals"]
    lens = ip[sel + 1] - ip[sel]
    idx = np.concatenate([np.arange(ip[s], ip[s + 1]) for s in sel]) \
        if len(sel) else np.zeros(0, dtype=np.int64)
    return np.r_[0, np.cumsum(lens)], b[idx], v[idx]


def kmeans_novelty(fit: tuple, d: tuple, k: int, seed: int) -> np.ndarray:
    import scipy.sparse as sp
    from sklearn.cluster import MiniBatchKMeans
    mk = lambda c: sp.csr_matrix((c[2], c[1], c[0]),
                                 shape=(len(c[0]) - 1, stdp.N_BINS))
    xf, xd = mk(fit), mk(d)
    km = MiniBatchKMeans(n_clusters=min(k, xf.shape[0]), random_state=seed,
                         batch_size=4096, n_init=3).fit(xf)
    c = km.cluster_centers_
    c = c / np.maximum(np.linalg.norm(c, axis=1, keepdims=True), 1e-12)
    return 1.0 - np.asarray((xd @ c.T).max(axis=1)).ravel()


def run(args: argparse.Namespace) -> None:
    t0 = time.time()
    con = lib.duck()
    lib.register_eval_views(con, args.eval)
    truth = con.execute("SELECT * FROM eval_truth").to_arrow_table().to_pylist()
    day = min(t["start_ts"] for t in truth).astimezone(_dt.timezone.utc).date()
    fit_days = bl._fit_days(con, day, args.fit_days)
    r = load_retinas(con, fit_days + [day], args.min_pkts)
    con.close()
    is_d = r["dt"] == np.datetime64(day)
    fsel, dsel = np.flatnonzero(~is_d), np.flatnonzero(is_d)
    fit, dd = _rows(r, fsel), _rows(r, dsel)
    w0 = stdp.init_prototypes(*fit, k=args.k, seed=args.seed)
    w = stdp.train(*fit, w0, eta=args.eta, epochs=args.epochs, seed=args.seed)
    rng = np.random.default_rng(args.seed)
    scores = {"stdp": stdp.novelty(*dd, w),
              "kmeans": kmeans_novelty(fit, dd, args.k, args.seed),
              "untrained_stdp": stdp.novelty(*dd, w0),
              "pkt_count": np.log(r["pkts"][dsel].astype(float)),
              "random": rng.random(len(dsel))}
    ips = [r["ip"][i] for i in dsel]
    rows = le.eval_clean(args.eval, ips, scores, truth, args.source_k, args.seed)
    from bench import harness2
    harness2.write_ranks("stdp_eval", args.eval, harness2.truth_ranks(
        args.eval, day, ips, scores, truth, args.seed))
    for x in rows:
        x["level"] = "source_stdp"
    md = [f"- injection set: `{args.eval}`, scored day {day}",
          f"- fit window: {fit_days[0]} .. {fit_days[-1]} ({len(fit_days)} "
          f"recorded days, {len(fsel):,} source-day retinas)",
          f"- scored: {len(dsel):,} sources with >= {args.min_pkts} unmasked "
          "packets that have a port",
          f"- network: K = {len(w)}, {stdp.N_BINS} buckets, eta {args.eta:g}, "
          f"{args.epochs} epochs; run time {time.time() - t0:.0f} s", "",
          "## STDP detectors and twins", ""]
    md += le._table(rows, args.source_k, list(scores))
    paths = lib.Report(name="stdp_eval", rows=rows, schema=bl.RESULT_SCHEMA,
                       markdown="\n".join(md) + "\n").write(suffix=args.eval)
    print(f"[stdp_eval] wrote {paths['parquet']} ({time.time() - t0:.0f}s)",
          file=sys.stderr)


def summary(names: list[str]) -> None:
    rows = []
    for n in names:
        rows += pq.read_table(OUT / f"stdp_eval_{n}.parquet").to_pylist()
        b = lib.REPORTS / "baselines" / f"baselines_{n}.parquet"
        if b.exists():
            # baselines.py ranks every source of D: keep its rows apart
            rows += [{**x, "detector": "bl_" + x["detector"]}
                     for x in pq.read_table(b).to_pylist()
                     if x["level"] == "source"]
    agg: dict[tuple, dict] = {}
    for x in rows:
        key = (x["detector"], x["archetype"], x["is_control"], x["k"])
        a = agg.setdefault(key, {"sets": set(), "n_truth": 0, "hits": 0,
                                 "chance_w": 0.0})
        a["sets"].add(x["eval_name"])
        a["n_truth"] += x["n_truth"]
        a["hits"] += x["hits"]
        a["chance_w"] += x["chance"] * x["n_truth"]
    out = [{"detector": k[0], "archetype": k[1], "is_control": k[2], "k": k[3],
            "n_sets": len(a["sets"]), "n_truth": a["n_truth"],
            "hits": a["hits"], "recall": a["hits"] / max(1, a["n_truth"]),
            "chance": a["chance_w"] / max(1, a["n_truth"])}
           for k, a in agg.items()]
    ks = sorted({x["k"] for x in out if x["detector"] in DETECTORS})
    rec = {(x["detector"], x["archetype"], x["k"]): x["recall"] for x in out
           if not x["is_control"]}
    md = [f"- sets: {len(names)} ({', '.join(names)})", "",
          "## Gate (ARCHITECTURE §9.1, Phase 5)", "",
          "| archetype | rival | stdp (sum) | rival (sum) | result |",
          "| --- | --- | ---: | ---: | --- |"]
    passed = True
    for a in GATE_ARCH:
        for rv in GATE_RIVALS:
            sv = [rec.get(("stdp", a, k), 0.0) for k in ks]
            rvv = [rec.get((rv, a, k), 0.0) for k in ks]
            ok = all(x >= y for x, y in zip(sv, rvv)) and sum(sv) > sum(rvv)
            passed &= ok
            md.append(f"| {a} | {rv} | {sum(sv):.2f} | {sum(rvv):.2f} | "
                      f"{'pass' if ok else 'failure'} |")
    md += ["", f"**Gate: {'pass' if passed else 'failure'}**", "",
           "## Pooled recall: STDP detectors and twins", ""]
    md += le._table([x for x in out if x["detector"] in DETECTORS], ks,
                    list(DETECTORS))
    base = [d for d in dict.fromkeys(x["detector"] for x in out)
            if d not in DETECTORS]
    if base:
        bks = sorted({x["k"] for x in out if x["detector"] in base})
        md += ["## Pooled recall: baselines.py (all sources of D)", ""]
        md += le._table([x for x in out if x["detector"] in base], bks, base)
    paths = lib.Report(name="stdp_eval", rows=out, schema=le.SUMMARY_SCHEMA,
                       markdown="\n".join(md) + "\n").write(suffix="summary")
    print(f"[stdp_eval] wrote {paths['markdown']}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--eval", metavar="NAME")
    g.add_argument("--summary", nargs="+", metavar="NAME")
    ap.add_argument("--fit-days", type=int, default=28)
    ap.add_argument("--min-pkts", type=int, default=5)
    ap.add_argument("--k", type=int, default=stdp.K)
    ap.add_argument("--eta", type=float, default=stdp.ETA)
    ap.add_argument("--epochs", type=int, default=stdp.EPOCHS)
    ap.add_argument("--source-k", type=int, nargs="+", default=[10, 50, 100])
    ap.add_argument("--seed", type=int, default=20261024)
    args = ap.parse_args()
    if args.summary:
        summary(args.summary)
    else:
        run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

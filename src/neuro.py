#!/usr/bin/env python3
"""
neuro — per-source neuromorphic scores for the features and risk steps.

Neuromorphic plan Phase 4 (docs/ARCHITECTURE.md §9.1 and §9.4).  For every
recorded day, each source with >= --min-pkts unmasked packets goes through
the sg.lif LIF / ALIF bank (the Phase 3 detector):

  change   ALIF rate shift: the largest sustained change of the source's
           own packet rate on the day
  reg      regularity: log(mean / std) of the pre-spike potential near the
           source's inter-arrival time (a metronome scores high)

Each readout is calibrated against the previous --cal-days recorded days
(sg.lif.calibrate: exceedance among the source-days with a similar packet
count, -log10).  A source-day is flagged when a calibrated readout is
>= --flag.

HDC choreography scores (Phase 1, sg.hdc; round 2 gate: both pass their
matched rff_* twins on rotating_actor, test and development sets): for every
recorded day D, the chainfp sessions of the previous --hdc-fit-days recorded
days plus D go through bench/hdc_eval.score_set with encoder seed 1, as in
the gate, and each source with a session on D gets

  hdc_proto  1 - best cosine of its D sessions against 128 sub-prototypes
             per fit day (a choreography that no known cluster explains)
  hdc_drift  fast vs slow prototype divergence over its own sessions
             (sources with >= 3 sessions; a source that changes behavior)

Both are calibrated like the LIF readouts, with the D session count in place
of the packet count, and a source-day is flagged at the same --flag.

The global arrival detector of Phase 2 adds one more column when
output/reports/arrival_eval/arrival_scores_full.parquet exists (from
``bench/arrival_eval.py --mode full``): the alarm minutes are the minutes
at or above the --arrival-rate alarms-per-day quantile of the
--arrival-detector score, and each source gets the number of alarm minutes
in which it sent packets, and whether its first packet is in one.

Rules of §9.3: the sensormask is applied and the LIF state resets at each
mask end; the per-day cache (output/.neuro_cache/) is outside the STAGE_IO
outputs; no score goes into bootstrap_label.

Output: output/reports/neuro/neuro.{parquet,md}      one row per source
        output/reports/neuro/neuro_days.parquet       one row per source-day
        output/reports/neuro/neuro_hdc_days.parquet   one row per source-day
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import os
import shutil
import sys
import tempfile
import time
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import hdc, lib, lif
from bench import arrival_series as ars

CACHE = lib.OUTPUT_DIR / ".neuro_cache"
OUT = lib.REPORTS / "neuro"
ARRIVAL_SCORES = lib.REPORTS / "arrival_eval" / "arrival_scores_full.parquet"

SCHEMA = pa.schema([
    ("src_ip",                pa.string()),
    ("lif_days",              pa.uint16()),
    ("lif_change_max",        pa.float32()),
    ("lif_reg_max",           pa.float32()),
    ("lif_max",               pa.float32()),
    ("lif_flag_days",         pa.uint16()),
    ("lif_best_day",          pa.date32()),
    ("arrival_alarm_minutes", pa.uint32()),
    ("arrival_first_in_alarm", pa.bool_()),
    ("hdc_days",              pa.uint16()),
    ("hdc_proto_max",         pa.float32()),
    ("hdc_drift_max",         pa.float32()),
    ("hdc_flag_days",         pa.uint16()),
    ("hdc_best_day",          pa.date32()),
])

HDC_DAY_SCHEMA = pa.schema([
    ("src_ip",     pa.string()),
    ("dt",         pa.date32()),
    ("n_sess",     pa.uint32()),
    ("proto",      pa.float32()),
    ("drift",      pa.float32()),
    ("proto_cal",  pa.float32()),
    ("drift_cal",  pa.float32()),
])
HDC_SEED = 1                  # the first encoder seed of the gate runs

DAY_SCHEMA = pa.schema([
    ("src_ip",     pa.string()),
    ("dt",         pa.date32()),
    ("n_pkts",     pa.uint32()),
    ("change",     pa.float32()),
    ("reg",        pa.float32()),
    ("change_cal", pa.float32()),
    ("reg_cal",    pa.float32()),
])


# ---------------------------------------------------------------- per day

def _cache_key(min_pkts: int) -> str:
    h = hashlib.sha1()
    h.update(Path(lif.__file__).read_bytes())
    h.update(str(min_pkts).encode())
    if lib.SENSORMASK_PATH.exists():
        h.update(lib.SENSORMASK_PATH.read_bytes())
    return h.hexdigest()[:12]


def _day_readouts(day: str, min_pkts: int, key: str) -> str:
    """Readouts of one day into the cache; returns the cache path."""
    path = CACHE / f"dt={day}" / f"readouts_{key}.parquet"
    part = lib.PARQUET / "packets" / f"dt={day}"
    if path.exists() and all(p.stat().st_mtime <= path.stat().st_mtime
                             for p in part.glob("*.parquet")):
        return str(path)
    from bench.lif_eval import load_day   # one loader for eval and stage
    con = lib.duck(memory_limit="3GB", threads=2)
    lib.register_views(con)
    mask_ends = np.array(sorted(e.timestamp() for _, e, _ in
                                lib.load_sensor_mask()))
    d = load_day(con, _dt.date.fromisoformat(day), min_pkts, mask_ends)
    con.close()
    if len(d["ips"]):
        med = lif.median_iat(d["t"], d["seg"], d["starts"])
        ch, rg = lif.bank_scores(d["t"], d["seg"], d["starts"], med)
        rg = np.where(np.isfinite(rg), rg, -1e9)
    else:
        ch = rg = np.zeros(0)
    tab = pa.table({"src_ip": pa.array(d["ips"], pa.string()),
                    "n_pkts": pa.array(d["n"], pa.uint32()),
                    "change": pa.array(ch, pa.float64()),
                    "reg": pa.array(rg, pa.float64())})
    path.parent.mkdir(parents=True, exist_ok=True)
    for old in path.parent.glob("readouts_*.parquet"):
        if old != path:
            old.unlink()
    tmp = path.with_suffix(".parquet.tmp")
    pq.write_table(tab, tmp, compression="zstd")
    tmp.replace(path)
    return str(path)


def lif_days(days: list[str], args: argparse.Namespace, log=sys.stderr
             ) -> pa.Table:
    key = _cache_key(args.min_pkts)
    t0 = time.time()
    paths: dict[str, str] = {}
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futs = {d: pool.submit(_day_readouts, d, args.min_pkts, key)
                for d in days}
        for i, d in enumerate(days):
            paths[d] = futs[d].result()
            if (i + 1) % 100 == 0 or i + 1 == len(days):
                print(f"[neuro] lif readouts {i + 1}/{len(days)} days "
                      f"{time.time() - t0:.0f}s", file=log)
    ref: deque = deque(maxlen=args.cal_days)
    parts = []
    for d in days:
        r = pq.read_table(paths[d])
        n = r["n_pkts"].to_numpy().astype(float)
        ch, rg = r["change"].to_numpy(), r["reg"].to_numpy()
        logn = np.log(np.maximum(n, 1))
        if len(ref) >= args.min_cal_days and len(n):
            fl = np.concatenate([x[0] for x in ref])
            fc = np.concatenate([x[1] for x in ref])
            fr = np.concatenate([x[2] for x in ref])
            cc = lif.calibrate(ch, logn, fc, fl)
            rc = lif.calibrate(rg, logn, fr, fl)
        else:
            cc = rc = np.full(len(n), np.nan)
        parts.append(pa.table({
            "src_ip": r["src_ip"],
            "dt": pa.array([_dt.date.fromisoformat(d)] * len(n), pa.date32()),
            "n_pkts": r["n_pkts"],
            "change": pa.array(ch, pa.float32()),
            "reg": pa.array(rg, pa.float32()),
            "change_cal": pa.array(cc, pa.float32()),
            "reg_cal": pa.array(rc, pa.float32())}, schema=DAY_SCHEMA))
        if len(n):
            ref.append((logn, ch, rg))
    return pa.concat_tables(parts) if parts else DAY_SCHEMA.empty_table()


# ---------------------------------------------------------------- hdc

def _hdc_key(fit_days: int, device: str = "cpu") -> str:
    from bench import hdc_eval
    import chainfp
    h = hashlib.sha1()
    for mod in (hdc, hdc_eval, chainfp):
        h.update(Path(mod.__file__).read_bytes())
    h.update(f"{fit_days}/{HDC_SEED}".encode())
    if device == "gpu":            # gpu prototypes differ from cpu (sg.hdc_gpu)
        h.update((Path(hdc.__file__).parent / "hdc_gpu.py").read_bytes())
        h.update(b"gpu")
    if lib.SENSORMASK_PATH.exists():
        h.update(lib.SENSORMASK_PATH.read_bytes())
    return h.hexdigest()[:12]


def _sessions_retry(con, he, days, tmp: Path, day: str) -> dict:
    """hdc_eval._sessions; on a DuckDB out-of-memory error, again with 4x
    the hash(src_ip) buckets (same rows, less memory), then with a 16 GB
    limit (one very large source cannot be split).  2026-05-20 (fit window
    with 2026-05-19) needs this at the 4 GB default."""
    import duckdb
    buckets = he._auto_buckets(con, days)
    for n, mem in ((buckets, None), (buckets * 4, None), (buckets * 4, "16GB")):
        if mem:
            con.execute(f"SET memory_limit = '{mem}'")
        try:
            return he._sessions(con, days, 30, n, tmp)
        except duckdb.OutOfMemoryException:
            for f in tmp.glob("sess_*.parquet"):
                f.unlink()
            for t in ('hc', 'hi'):          # hdc_eval._sessions temp tables
                con.execute(f"DROP TABLE IF EXISTS {t}")
            print(f"[neuro] hdc {day}: DuckDB out of memory with {n} "
                  f"buckets{', ' + mem if mem else ''}", file=sys.stderr)
    raise RuntimeError(f"[neuro] hdc {day}: sessions do not fit in 16 GB")


def _day_hdc(day: str, fit_days: int, key: str, device: str = "cpu") -> str:
    """hdc_proto / hdc_drift of one day into the cache; returns the path.
    A day with fewer than ``fit_days`` recorded days before it has no
    rows."""
    path = CACHE / f"dt={day}" / f"hdc_{key}.parquet"
    part = lib.PARQUET / "packets" / f"dt={day}"
    if path.exists() and all(p.stat().st_mtime <= path.stat().st_mtime
                             for p in part.glob("*.parquet")):
        return str(path)
    from bench import baselines as bl, hdc_eval as he
    d = _dt.date.fromisoformat(day)
    con = lib.duck(memory_limit="4GB", threads=2)
    lib.register_views(con)
    fit = bl._fit_days(con, d, fit_days)
    ips, n_sess, proto, drift = [], np.zeros(0), np.zeros(0), np.zeros(0)
    if len(fit) == fit_days:
        (lib.OUTPUT_DIR / ".hdc_tmp").mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix=f"neuro_{day}_",
                                    dir=lib.OUTPUT_DIR / ".hdc_tmp"))
        try:
            s = _sessions_retry(con, he, fit + [d], tmp, day)
            con.close()
            con = None
            is_d = s["di"] == len(fit)
            iids, n_sess = np.unique(s["iid"][is_d], return_counts=True)
            ips = [s["ips"][i] for i in iids]
            a = argparse.Namespace(
                only=["hdc_proto", "hdc_drift"], dim=hdc.D_DEFAULT,
                noise_z=5.0, protos=128, alpha_fast=0.5, alpha_slow=0.05,
                min_sessions=3, align_power=4.0, align_weight="distinct",
                device=device)
            sc = he.score_set(s, fit, ips, [HDC_SEED], a, tmp)[HDC_SEED]
            proto, drift = sc["hdc_proto"], sc["hdc_drift"]
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            if device == "gpu":
                # the GPU uses host RAM here: give the pool back each day
                import torch
                torch.cuda.empty_cache()
    if con is not None:
        con.close()
    tab = pa.table({"src_ip": pa.array(ips, pa.string()),
                    "n_sess": pa.array(n_sess, pa.uint32()),
                    "proto": pa.array(proto, pa.float64()),
                    "drift": pa.array(drift, pa.float64())})
    path.parent.mkdir(parents=True, exist_ok=True)
    for old in path.parent.glob("hdc_*.parquet"):
        if old != path:
            old.unlink()
    tmp_p = path.with_suffix(".parquet.tmp")
    pq.write_table(tab, tmp_p, compression="zstd")
    tmp_p.replace(path)
    return str(path)


def hdc_days(days: list[str], args: argparse.Namespace, log=sys.stderr
             ) -> pa.Table:
    if args.hdc_device == "auto":
        try:
            import torch
            args.hdc_device = "gpu" if torch.cuda.is_available() else "cpu"
        except ImportError:
            args.hdc_device = "cpu"
    if args.hdc_workers is None:
        args.hdc_workers = (2 if args.hdc_device == "gpu"
                            else max(1, min(4, (os.cpu_count() or 4) // 6)))
    print(f"[neuro] hdc device: {args.hdc_device}, "
          f"{args.hdc_workers} workers", file=log)
    key = _hdc_key(args.hdc_fit_days, args.hdc_device)
    t0 = time.time()
    paths: dict[str, str] = {}
    with ProcessPoolExecutor(max_workers=args.hdc_workers) as pool:
        futs = {d: pool.submit(_day_hdc, d, args.hdc_fit_days, key,
                               args.hdc_device)
                for d in days}
        for i, d in enumerate(days):
            paths[d] = futs[d].result()
            if (i + 1) % 50 == 0 or i + 1 == len(days):
                print(f"[neuro] hdc scores {i + 1}/{len(days)} days "
                      f"{time.time() - t0:.0f}s", file=log)
    ref: deque = deque(maxlen=args.cal_days)
    parts = []
    for d in days:
        r = pq.read_table(paths[d])
        n = r["n_sess"].to_numpy().astype(float)
        pr, dr = r["proto"].to_numpy(), r["drift"].to_numpy()
        logn = np.log(np.maximum(n, 1))
        if len(ref) >= args.min_cal_days and len(n):
            fl = np.concatenate([x[0] for x in ref])
            fp = np.concatenate([x[1] for x in ref])
            fd = np.concatenate([x[2] for x in ref])
            pc = lif.calibrate(pr, logn, fp, fl)
            dc = lif.calibrate(dr, logn, fd, fl)
        else:
            pc = dc = np.full(len(n), np.nan)
        parts.append(pa.table({
            "src_ip": r["src_ip"],
            "dt": pa.array([_dt.date.fromisoformat(d)] * len(n), pa.date32()),
            "n_sess": r["n_sess"],
            "proto": pa.array(pr, pa.float32()),
            "drift": pa.array(dr, pa.float32()),
            "proto_cal": pa.array(pc, pa.float32()),
            "drift_cal": pa.array(dc, pa.float32())}, schema=HDC_DAY_SCHEMA))
        if len(n):
            ref.append((logn, pr, dr))
    return (pa.concat_tables(parts) if parts
            else HDC_DAY_SCHEMA.empty_table())


# ---------------------------------------------------------------- arrival

def arrival_alarms(detector: str, rate: float) -> np.ndarray | None:
    """Alarm minute starts (epoch s) of the Phase 2 detector at ``rate``
    alarm minutes per day, or None when there is no full-mode score file."""
    if not ARRIVAL_SCORES.exists():
        return None
    t = pq.read_table(ARRIVAL_SCORES, columns=["minute", detector])
    v = t[detector].to_numpy(zero_copy_only=False).astype(float)
    m = t["minute"].cast(pa.int64()).to_numpy() / 1e6
    fin = np.isfinite(v)
    if not fin.any():
        return None
    th = np.quantile(v[fin], 1 - rate / 1440)
    return np.sort(m[fin & (v >= th)])


def arrival_columns(alarms: np.ndarray) -> dict:
    con = lib.duck()
    lib.register_views(con)
    tbl = pa.table({"minute": pa.array((alarms * 1e6).astype(np.int64),
                                       type=pa.timestamp("us", tz="UTC"))})
    con.register("alarm_tbl", tbl)
    days = sorted({_dt.datetime.fromtimestamp(a, _dt.timezone.utc).date()
                   for a in alarms})
    dpred = "dt IN (" + ", ".join(f"DATE '{d}'" for d in days) + ")"
    rows = con.execute(f"""
        WITH a AS (SELECT DISTINCT minute FROM alarm_tbl),
        act AS (
            SELECT src_ip, count(DISTINCT date_trunc('minute', ts)) AS n
            FROM packets SEMI JOIN a ON date_trunc('minute', packets.ts) = a.minute
            WHERE {dpred} AND {ars.NOT_NTP}
            GROUP BY src_ip
        ),
        first AS (
            SELECT src_ip, date_trunc('minute', min(ts)) AS fm FROM packets
            WHERE {ars.NOT_NTP} GROUP BY src_ip
        )
        SELECT act.src_ip, act.n,
               first.fm IN (SELECT minute FROM a) AS first_in
        FROM act JOIN first USING (src_ip)
    """).fetchall()
    con.close()
    return {r[0]: (int(r[1]), bool(r[2])) for r in rows}


# ---------------------------------------------------------------- run

def run(args: argparse.Namespace) -> lib.Report:
    t0 = time.time()
    con = lib.duck()
    lib.register_views(con)
    days = [str(r[0]) for r in con.execute(
        "SELECT DISTINCT dt FROM packets ORDER BY dt").fetchall()]
    con.close()
    days = [d for d in days if (not args.start or d >= args.start)
            and (not args.end or d <= args.end)]
    per_day = lif_days(days, args)
    hdc_day = hdc_days(days, args)
    OUT.mkdir(parents=True, exist_ok=True)
    for name, t in (("neuro_days", per_day), ("neuro_hdc_days", hdc_day)):
        tmp = OUT / f"{name}.parquet.tmp"
        pq.write_table(t, tmp, compression="zstd")
        tmp.replace(OUT / f"{name}.parquet")

    con = lib.duck()
    con.register("d", per_day)
    agg = con.execute(f"""
        SELECT src_ip, count(*) AS lif_days,
               max(change_cal) AS lif_change_max, max(reg_cal) AS lif_reg_max,
               max(greatest(change_cal, reg_cal)) AS lif_max,
               count(*) FILTER (WHERE greatest(change_cal, reg_cal) >= {args.flag})
                   AS lif_flag_days,
               arg_max(dt, greatest(change_cal, reg_cal)) AS lif_best_day
        FROM d WHERE change_cal IS NOT NULL AND NOT isnan(change_cal)
        GROUP BY src_ip
    """).to_arrow_table()
    con.register("h", hdc_day)
    hagg = {r[0]: r[1:] for r in con.execute(f"""
        SELECT src_ip, count(*), max(proto_cal), max(drift_cal),
               count(*) FILTER (WHERE greatest(proto_cal, drift_cal) >= {args.flag}),
               arg_max(dt, greatest(proto_cal, drift_cal))
        FROM h WHERE proto_cal IS NOT NULL AND NOT isnan(proto_cal)
        GROUP BY src_ip
    """).fetchall()}
    con.close()
    alarms = arrival_alarms(args.arrival_detector, args.arrival_rate)
    arr = arrival_columns(alarms) if alarms is not None and len(alarms) else {}
    ips = agg["src_ip"].to_pylist()
    seen = set(ips)
    extra = [ip for ip in list(arr) + list(hagg) if ip not in seen
             and not seen.add(ip)]
    none5 = (0, 0.0, 0.0, 0, None)
    hcol = lambda j: [hagg.get(ip, none5)[j] for ip in ips + extra]
    n_all = len(ips) + len(extra)
    pad = lambda col, fill: col.to_pylist() + [fill] * len(extra)
    tab = pa.table({
        "src_ip": ips + extra,
        "lif_days": pa.array(pad(agg["lif_days"], 0), pa.uint16()),
        "lif_change_max": pa.array(pad(agg["lif_change_max"], 0.0), pa.float32()),
        "lif_reg_max": pa.array(pad(agg["lif_reg_max"], 0.0), pa.float32()),
        "lif_max": pa.array(pad(agg["lif_max"], 0.0), pa.float32()),
        "lif_flag_days": pa.array(pad(agg["lif_flag_days"], 0), pa.uint16()),
        "lif_best_day": pa.array(pad(agg["lif_best_day"], None), pa.date32()),
        "arrival_alarm_minutes": pa.array(
            [arr.get(ip, (0, False))[0] for ip in ips + extra], pa.uint32()),
        "arrival_first_in_alarm": pa.array(
            [arr.get(ip, (0, False))[1] for ip in ips + extra], pa.bool_()),
        "hdc_days": pa.array(hcol(0), pa.uint16()),
        "hdc_proto_max": pa.array(hcol(1), pa.float32()),
        "hdc_drift_max": pa.array(hcol(2), pa.float32()),
        "hdc_flag_days": pa.array(hcol(3), pa.uint16()),
        "hdc_best_day": pa.array(hcol(4), pa.date32()),
    }, schema=SCHEMA)
    flagged = int(np.sum(np.asarray(tab["lif_flag_days"]) > 0))
    hflagged = int(np.sum(np.asarray(tab["hdc_flag_days"]) > 0))
    md = [f"- recorded days: {len(days)} ({days[0]} to {days[-1]})",
          f"- source-days scored (>= {args.min_pkts} unmasked packets): "
          f"{per_day.num_rows:,}",
          f"- sources: {n_all:,}; sources with a flagged day "
          f"(calibrated readout >= {args.flag}): {flagged:,}",
          f"- HDC source-days scored (a session on D, "
          f"{args.hdc_fit_days} fit days before it): {hdc_day.num_rows:,}; "
          f"sources with a flagged HDC day: {hflagged:,}",
          f"- calibration: the previous {args.cal_days} recorded days "
          f"(no score for the first {args.min_cal_days})",
          (f"- arrival alarms: {len(alarms):,} minutes of `{args.arrival_detector}` "
           f"at {args.arrival_rate:g} per day; {len(arr):,} sources sent "
           "packets in an alarm minute" if alarms is not None else
           "- arrival alarms: no arrival_scores_full.parquet (run "
           "bench/arrival_eval.py --mode full)"),
          f"- run time: {time.time() - t0:.0f} s", "",
          "## Top sources by the LIF score", "",
          "| src_ip | best day | change | regularity | flagged days |",
          "| --- | --- | ---: | ---: | ---: |"]
    top = sorted(tab.to_pylist(), key=lambda r: -(r["lif_max"] or 0))[:25]
    md += [f"| {r['src_ip']} | {r['lif_best_day']} | {r['lif_change_max']:.1f} | "
           f"{r['lif_reg_max']:.1f} | {r['lif_flag_days']} |" for r in top]
    md += ["", "## Top sources by the HDC score", "",
           "| src_ip | best day | proto | drift | flagged days |",
           "| --- | --- | ---: | ---: | ---: |"]
    top = sorted(tab.to_pylist(), key=lambda r: -max(r["hdc_proto_max"] or 0,
                                                     r["hdc_drift_max"] or 0))[:25]
    md += [f"| {r['src_ip']} | {r['hdc_best_day']} | {r['hdc_proto_max']:.1f} | "
           f"{r['hdc_drift_max']:.1f} | {r['hdc_flag_days']} |" for r in top]
    return lib.Report(name="neuro", rows=tab, schema=SCHEMA,
                      markdown="\n".join(md) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--start", help="first day YYYY-MM-DD (default: all)")
    ap.add_argument("--end", help="last day YYYY-MM-DD (default: all)")
    ap.add_argument("--min-pkts", type=int, default=20)
    ap.add_argument("--cal-days", type=int, default=28)
    ap.add_argument("--min-cal-days", type=int, default=3)
    ap.add_argument("--flag", type=float, default=4.0,
                    help="calibrated -log10 exceedance that flags a source-day")
    ap.add_argument("--workers", type=int,
                    default=max(1, min(8, (os.cpu_count() or 4) // 4)))
    ap.add_argument("--hdc-fit-days", type=int, default=7,
                    help="recorded days before D in the HDC fit window")
    ap.add_argument("--hdc-workers", type=int, default=None,
                    help="parallel HDC days (default: 2 on gpu, where 4 ran "
                         "the host out of memory on 2026-10-27; cpu count/6 "
                         "up to 4 on cpu, about 3.5 GB each)")
    ap.add_argument("--hdc-device", choices=("auto", "cpu", "gpu"), default="auto",
                    help="gpu: encode and hdc_proto on the GPU (sg.hdc_gpu, "
                         "bench/hdc_gpu_check.py); auto = gpu when PyTorch "
                         "sees one.  Own cache key: gpu hdc_proto keeps exact "
                         "k-means ties, the cpu float32 path does not")
    # Phase 2 full-span gate (ARCHITECTURE §9.6): ngrc_htm 97.6 FA/yr,
    # stl_z 10.3.  tail5x (0.9) is the rule that found E1 and E3 (circular).
    ap.add_argument("--arrival-detector", default="stl_z")
    ap.add_argument("--arrival-rate", type=float, default=1.0,
                    help="arrival alarm minutes per day")
    args = ap.parse_args()
    paths = run(args).write()
    print(f"[neuro] wrote {paths['parquet']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

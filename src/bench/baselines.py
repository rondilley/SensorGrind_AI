#!/usr/bin/env python3
"""
bench/baselines — the yardstick every new anomaly detector must beat.

Runs a fixed set of simple and classical detectors over one adversarysim
injection set (``adversarysim.py --inject NAME --day D``) and scores how
well each one ranks the injected archetypes.  A neuromorphic detector
(SNN / HDC / reservoir / HTM) only earns a place in the pipeline if it
beats these numbers on the same injection set; this stage gives the
numbers.

Two levels, each fit on the ``--fit-days`` recorded days before D (minus
the sensormask intervals) and scored on D:

  source   one score per source IP on D
           random, pkt_count, n_ports, new_port_24 (ports this /24 never
           hit in the fit window), iforest + ecod (pyod, fit on
           per-source-day feature vectors from the fit window)
  global   one score per minute of D
           random, hod_z (per-series z against the fit window's
           hour-of-day mean/std), stl_z (per-minute residual against a
           robust STL trend + daily season fit on 15-minute means),
           port_hour_z (hourly per-port count z, top 1,024 ports)

Metrics (no point adjustment, fixed alert budgets):
  source   recall@k of each archetype's IPs among all D sources, the
           chance level k/N, and the median rank.  control_replay rows
           are re-addressed recorded sources: a good detector leaves
           them unflagged.
  global   whether any minute of the archetype's window is in the top-k
           minutes, the hypergeometric chance of that, and the time to
           detection.  Windows longer than --max-global-window-min are
           skipped (an all-day beacon "hits" any detector by chance).

Output: output/reports/baselines/baselines_<NAME>.{parquet,md}
"""
from __future__ import annotations

import argparse
import datetime as _dt
import math
import sys
from pathlib import Path

import numpy as np
import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("eval_name",   pa.string()),
    ("level",       pa.string()),
    ("detector",    pa.string()),
    ("archetype",   pa.string()),
    ("is_control",  pa.bool_()),
    ("n_truth",     pa.uint32()),
    ("k",           pa.uint32()),
    ("hits",        pa.uint32()),
    ("recall",      pa.float64()),
    ("chance",      pa.float64()),
    ("median_rank", pa.float64()),
    ("ttd_s",       pa.float64()),
])

STL_BIN = 15   # minutes per STL bin (divides 1440)

FEATURES = ["log_pkts", "log_ports", "syn_share", "n_ttl", "n_win",
            "log_active_min", "log_span_s", "iat_mean_log", "iat_std_log",
            "log_max_per_min"]


# ---------------------------------------------------------------- pure helpers
# Side-effect-free so they unit-test without the corpus.

def ranks_desc(scores: np.ndarray, seed: int = 0) -> np.ndarray:
    """1-based rank of each score, highest first, ties broken at random
    (a constant detector must not look good by tie order)."""
    rng = np.random.default_rng(seed)
    order = np.lexsort((rng.random(len(scores)), -scores))
    r = np.empty(len(scores), dtype=np.int64)
    r[order] = np.arange(1, len(scores) + 1)
    return r


def hit_chance(n: int, w: int, k: int) -> float:
    """P(at least one of ``w`` window minutes lands in a random top-``k``
    of ``n`` minutes): 1 - C(n-w, k) / C(n, k)."""
    if w <= 0 or k <= 0:
        return 0.0
    if n - w < k:
        return 1.0
    log_miss = (math.lgamma(n - w + 1) - math.lgamma(n - w - k + 1)
                - math.lgamma(n + 1) + math.lgamma(n - k + 1))
    return 1.0 - math.exp(log_miss)


def robust_z(x: np.ndarray, ref: np.ndarray) -> np.ndarray:
    """z against the median/MAD of ``ref`` (MAD floored to stay finite)."""
    med = np.nanmedian(ref)
    mad = np.nanmedian(np.abs(ref - med)) * 1.4826
    return (x - med) / max(mad, 1e-9)


def interval_mask(minutes: np.ndarray, mask: list) -> np.ndarray:
    """True for minute starts (epoch seconds) that overlap a mask interval."""
    out = np.zeros(len(minutes), dtype=bool)
    for s, e, _ in mask:
        s_ep, e_ep = s.timestamp(), e.timestamp()
        out |= (minutes + 60 > s_ep) & (minutes < e_ep)
    return out


# ---------------------------------------------------------------- data access

def _fit_days(con, day: _dt.date, n: int) -> list[_dt.date]:
    rows = con.execute(f"""
        SELECT DISTINCT dt FROM packets WHERE dt < DATE '{day}'
        ORDER BY dt DESC LIMIT {n}
    """).fetchall()
    return sorted(r[0] for r in rows)


def _days_pred(days: list[_dt.date]) -> str:
    return "dt IN (" + ", ".join(f"DATE '{d}'" for d in days) + ")"


def _source_features(con, days_pred: str) -> dict:
    """Per (src_ip, dt) feature matrix over the unmasked packets of days."""
    t = con.execute(f"""
        WITH p AS (
            SELECT src_ip, dt, ts, dst_port, tcp_flags, ttl, tcp_win
            FROM packets WHERE {days_pred} AND {lib.mask_predicate('ts')}
        ), g AS (
            SELECT src_ip, dt,
                   epoch_us(ts) - lag(epoch_us(ts)) OVER
                       (PARTITION BY src_ip, dt ORDER BY ts) AS d_us,
                   date_trunc('minute', ts) AS minute
            FROM p
        ), iat AS (
            SELECT src_ip, dt,
                   avg(log10(d_us + 1))         AS iat_mean_log,
                   stddev_pop(log10(d_us + 1))  AS iat_std_log
            FROM g WHERE d_us IS NOT NULL GROUP BY src_ip, dt
        ), pm AS (
            SELECT src_ip, dt, max(n) AS max_per_min FROM (
                SELECT src_ip, dt, minute, count(*) AS n FROM g
                GROUP BY src_ip, dt, minute) GROUP BY src_ip, dt
        ), base AS (
            SELECT src_ip, dt, count(*) AS pkts,
                   count(DISTINCT dst_port) AS ports,
                   avg(CASE WHEN tcp_flags = 2 THEN 1.0 ELSE 0.0 END) AS syn_share,
                   count(DISTINCT ttl) AS n_ttl,
                   count(DISTINCT tcp_win) AS n_win,
                   count(DISTINCT date_trunc('minute', ts)) AS active_min,
                   epoch(max(ts) - min(ts)) AS span_s
            FROM p GROUP BY src_ip, dt
        )
        SELECT b.src_ip, b.dt, b.pkts, b.ports, b.syn_share, b.n_ttl, b.n_win,
               b.active_min, b.span_s,
               coalesce(i.iat_mean_log, -1.0) AS iat_mean_log,
               coalesce(i.iat_std_log, -1.0)  AS iat_std_log,
               pm.max_per_min
        FROM base b
        LEFT JOIN iat i USING (src_ip, dt)
        LEFT JOIN pm USING (src_ip, dt)
        -- fixed row order: random scores, tie breaks and the IForest
        -- subsample are all index-based, so an unordered result changes
        -- the exit-gate numbers from run to run
        ORDER BY b.src_ip, b.dt
    """).to_arrow_table()
    ips = t["src_ip"].to_pylist()
    keep = np.array([lib.is_real_external_ip(ip) for ip in ips], dtype=bool)
    col = lambda c: np.asarray(t[c].to_numpy(), dtype=float)[keep]
    x = np.column_stack([
        np.log1p(col("pkts")), np.log1p(col("ports")), col("syn_share"),
        col("n_ttl"), col("n_win"), np.log1p(col("active_min")),
        np.log1p(col("span_s")), col("iat_mean_log"), col("iat_std_log"),
        np.log1p(col("max_per_min")),
    ])
    return {"src_ip": [ip for ip, k in zip(ips, keep) if k],
            "pkts": col("pkts"), "ports": col("ports"),
            "x": np.nan_to_num(x, nan=0.0)}


def _new_port_24(con, fit_pred: str, day: _dt.date, ips: list[str]) -> np.ndarray:
    """Distinct ports each D source hit that its /24 never hit in the fit
    window (IPv4 only; others score 0)."""
    rows = dict(con.execute(f"""
        WITH d AS (
            SELECT DISTINCT src_ip,
                   regexp_extract(src_ip, '^(\\d+\\.\\d+\\.\\d+)\\.', 1) AS c24,
                   dst_port
            FROM packets WHERE dt = DATE '{day}' AND {lib.mask_predicate('ts')}
              AND dst_port IS NOT NULL
        ), f AS (
            SELECT DISTINCT
                   regexp_extract(src_ip, '^(\\d+\\.\\d+\\.\\d+)\\.', 1) AS c24,
                   dst_port
            FROM packets WHERE {fit_pred} AND {lib.mask_predicate('ts')}
              AND dst_port IS NOT NULL
        )
        SELECT d.src_ip, count(*) FILTER (WHERE f.c24 IS NULL)
        FROM d LEFT JOIN f ON d.c24 = f.c24 AND d.dst_port = f.dst_port
        WHERE d.c24 <> ''
        GROUP BY d.src_ip
    """).fetchall())
    return np.array([rows.get(ip, 0) for ip in ips], dtype=float)


def _minute_series(con, days: list[_dt.date], first_seen_pred: str) -> dict:
    """Per-minute global series over ``days``.  new_src counts sources whose
    first packet in (fit window + D) falls in that minute."""
    t0 = _dt.datetime.combine(days[0], _dt.time(), _dt.timezone.utc)
    t1 = _dt.datetime.combine(days[-1], _dt.time(), _dt.timezone.utc) \
        + _dt.timedelta(days=1)
    n = int((t1 - t0).total_seconds() // 60)
    rows = con.execute(f"""
        WITH p AS (
            SELECT ts, src_ip, dst_port, tcp_flags FROM packets
            WHERE {_days_pred(days)}
        ), fs AS (
            SELECT src_ip, min(ts) AS first_ts FROM packets
            WHERE {first_seen_pred} GROUP BY src_ip
        ), m AS (
            SELECT date_trunc('minute', ts) AS minute, count(*) AS pkts,
                   count(DISTINCT src_ip) AS n_src,
                   count(DISTINCT dst_port) AS n_ports,
                   avg(CASE WHEN tcp_flags = 2 THEN 1.0 ELSE 0.0 END) AS syn_share
            FROM p GROUP BY minute
        ), nw AS (
            SELECT date_trunc('minute', first_ts) AS minute, count(*) AS new_src
            FROM fs GROUP BY minute
        )
        SELECT epoch(m.minute)::BIGINT, m.pkts, m.n_src, m.n_ports, m.syn_share,
               coalesce(nw.new_src, 0)
        FROM m LEFT JOIN nw USING (minute)
    """).fetchall()
    base = t0.timestamp()
    out = {k: np.zeros(n) for k in ("pkts", "n_src", "n_ports", "syn_share",
                                    "new_src")}
    for ep, pk, ns, np_, ss, nw in rows:
        i = int((ep - base) // 60)
        if 0 <= i < n:
            out["pkts"][i], out["n_src"][i] = pk, ns
            out["n_ports"][i], out["syn_share"][i] = np_, ss or 0.0
            out["new_src"][i] = nw
    out["minute"] = base + 60.0 * np.arange(n)
    return out


def _port_hour_z(con, fit_pred: str, day: _dt.date, n_fit_hours: int,
                 top: int = 1024) -> np.ndarray:
    """Max over ports of the D-hour count z against that port's fit-window
    hourly mean/var (Poisson floor).  Returns 24 hourly scores."""
    rows = con.execute(f"""
        WITH f AS (
            SELECT dst_port, count(*) AS n FROM packets
            WHERE {fit_pred} AND {lib.mask_predicate('ts')} AND dst_port IS NOT NULL
            GROUP BY dst_port ORDER BY n DESC LIMIT {top}
        ), fh AS (
            -- ports outside the top list share one "other" bucket (-1)
            SELECT coalesce(f.dst_port, -1) AS dst_port,
                   date_trunc('hour', ts) AS h, count(*) AS n
            FROM packets p LEFT JOIN f USING (dst_port)
            WHERE {fit_pred} AND {lib.mask_predicate('ts')}
            GROUP BY ALL
        ), st AS (
            SELECT dst_port, sum(n) AS s, sum(n * n) AS s2 FROM fh GROUP BY dst_port
        ), dh AS (
            SELECT coalesce(f.dst_port, -1) AS port,
                   hour(timezone('UTC', ts)) AS hr, count(*) AS n
            FROM packets p LEFT JOIN f USING (dst_port)
            WHERE dt = DATE '{day}' AND {lib.mask_predicate('ts')}
            GROUP BY ALL
        )
        SELECT dh.hr, dh.port, dh.n, st.s, st.s2
        FROM dh LEFT JOIN st ON dh.port = st.dst_port
    """).fetchall()
    score = np.zeros(24)
    for hr, port, n, s, s2 in rows:
        if s is None:
            mu, var = 0.0, 0.0           # bucket unseen in the fit window
        else:
            mu = s / n_fit_hours
            var = max(s2 / n_fit_hours - mu * mu, 0.0)
        z = (n - mu) / math.sqrt(var + mu + 1.0)
        score[hr] = max(score[hr], z)
    return score


# ---------------------------------------------------------------- detectors

def source_scores(fit: dict, d: dict, new24: np.ndarray, seed: int) -> dict:
    from pyod.models.ecod import ECOD
    from pyod.models.iforest import IForest
    rng = np.random.default_rng(seed)
    xf = fit["x"]
    if len(xf) > 200_000:
        xf = xf[rng.choice(len(xf), 200_000, replace=False)]
    out = {"random": rng.random(len(d["src_ip"])),
           "pkt_count": d["pkts"], "n_ports": d["ports"],
           "new_port_24": new24}
    for name, model in (("iforest", IForest(random_state=seed)),
                        ("ecod", ECOD())):
        model.fit(xf)
        out[name] = model.decision_function(d["x"])
    return out


def global_scores(ser: dict, use: np.ndarray, masked: np.ndarray,
                  fit_idx: np.ndarray, day_idx: np.ndarray,
                  port_hour: np.ndarray, seed: int) -> dict:
    """``use`` = minute indices of the recorded days (whole UTC days, so the
    daily phase survives the concatenation across unrecorded gaps)."""
    from statsmodels.tsa.seasonal import STL
    rng = np.random.default_rng(seed)
    hod = ((ser["minute"] // 3600) % 24).astype(int)
    count_series = ("pkts", "n_src", "n_ports", "new_src")

    hz = np.zeros(len(day_idx))
    hod_med: dict[str, np.ndarray] = {}
    for k in count_series + ("syn_share",):
        x = ser[k]
        mu = np.zeros(24); sd = np.ones(24); med = np.zeros(24)
        for h in range(24):
            ref = x[fit_idx][hod[fit_idx] == h]
            if len(ref):
                mu[h], sd[h] = ref.mean(), max(ref.std(), 1e-9)
                med[h] = np.median(ref)
        hod_med[k] = med
        z = (x[day_idx] - mu[hod[day_idx]]) / sd[hod[day_idx]]
        hz = np.maximum(hz, np.abs(z) if k == "syn_share" else z)

    stl = np.full(len(day_idx), -np.inf)
    pos = np.full(len(ser["minute"]), -1)
    pos[use] = np.arange(len(use))
    for k in ("pkts", "n_src", "new_src"):
        x = ser[k][use].astype(float)
        if len(x) < 2 * 1440 + 1:
            continue
        # Masked minutes inside a recorded day carry no observation; fill
        # them with the fit hour-of-day median so they do not read as zeros.
        m = masked[use]
        x[m] = hod_med[k][hod[use][m]]
        # Robust STL at period 1440 costs ~3 min per series; fit trend +
        # season on 15-minute means (period 96, <1 s) and keep the residual
        # per minute.  ``use`` is whole days, so the reshape is exact.
        dec = STL(x.reshape(-1, STL_BIN).mean(1), period=1440 // STL_BIN,
                  robust=True).fit()
        res = x - np.repeat(dec.trend + dec.seasonal, STL_BIN)
        stl = np.maximum(stl, robust_z(res[pos[day_idx]], res[pos[fit_idx]]))

    hours = ((ser["minute"][day_idx] // 3600) % 24).astype(int)
    return {"random": rng.random(len(day_idx)), "hod_z": hz,
            "stl_z": stl, "port_hour_z": port_hour[hours]}


# ---------------------------------------------------------------- evaluation

def eval_source(name: str, ips: list[str], scores: dict, truth: list[dict],
                ks: list[int], seed: int) -> list[dict]:
    pos = {ip: i for i, ip in enumerate(ips)}
    groups: dict[tuple, list[int]] = {}
    for t in truth:
        if t["level"] == "source" and t["src_ip"] in pos:
            groups.setdefault((t["archetype"], t["is_control"]), []).append(
                pos[t["src_ip"]])
    out = []
    for det, s in scores.items():
        r = ranks_desc(np.asarray(s, dtype=float), seed)
        for (arch, ctrl), idx in groups.items():
            rk = r[idx]
            for k in ks:
                hits = int((rk <= k).sum())
                out.append({
                    "eval_name": name, "level": "source", "detector": det,
                    "archetype": arch, "is_control": ctrl,
                    "n_truth": len(idx), "k": k, "hits": hits,
                    "recall": hits / len(idx), "chance": min(1.0, k / len(r)),
                    "median_rank": float(np.median(rk)), "ttd_s": None,
                })
    return out


def eval_global(name: str, minutes: np.ndarray, valid: np.ndarray,
                scores: dict, truth: list[dict], ks: list[int],
                max_window_min: int, seed: int) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for t in truth:
        groups.setdefault((t["archetype"], t["is_control"]), []).append(t)
    out = []
    n = int(valid.sum())
    for (arch, ctrl), ts in groups.items():
        st = min(t["start_ts"] for t in ts).timestamp()
        en = max(t["end_ts"] for t in ts).timestamp()
        win = (minutes + 60 > st) & (minutes <= en) & valid
        w = int(win.sum())
        if w == 0 or w > max_window_min:
            continue
        for det, s in scores.items():
            s = np.where(valid, np.asarray(s, dtype=float), -np.inf)
            r = ranks_desc(s, seed)
            for k in ks:
                top = win & (r <= k)
                first = minutes[top].min() if top.any() else None
                out.append({
                    "eval_name": name, "level": "global", "detector": det,
                    "archetype": arch, "is_control": ctrl, "n_truth": w,
                    "k": k, "hits": int(top.sum()),
                    "recall": 1.0 if top.any() else 0.0,
                    "chance": hit_chance(n, w, k),
                    "median_rank": float(np.median(r[win])),
                    "ttd_s": (max(0.0, first - st) if first is not None
                              else None),
                })
    return out


def _markdown(rows: list[dict], name: str, day, fit_days, n_src, n_min) -> str:
    md = [f"- injection set: `{name}`, scored day {day}",
          f"- fit window: {fit_days[0]} .. {fit_days[-1]} "
          f"({len(fit_days)} recorded days, sensormask applied)",
          f"- scored: {n_src:,} sources, {n_min:,} unmasked minutes", "",
          "Recall at a fixed alert budget, no point adjustment.  `chance` "
          "is what a random ranking scores.  control_replay rows should "
          "stay near chance.", ""]
    for level, title in (("source", "Source level"), ("global", "Global level")):
        sub = [r for r in rows if r["level"] == level]
        if not sub:
            continue
        ks = sorted({r["k"] for r in sub})
        dets = list(dict.fromkeys(r["detector"] for r in sub))
        md += [f"## {title}", ""]
        for k in ks:
            md += [f"### k = {k}", "",
                   "| archetype | n | chance | " + " | ".join(dets) + " |",
                   "| --- | ---: | ---: | " + " | ".join("---:" for _ in dets) + " |"]
            archs = list(dict.fromkeys((r["archetype"], r["is_control"])
                                       for r in sub if r["k"] == k))
            for arch, ctrl in archs:
                cells = {r["detector"]: r for r in sub if r["k"] == k
                         and r["archetype"] == arch and r["is_control"] == ctrl}
                any_r = next(iter(cells.values()))
                label = arch + (" (control)" if ctrl else "")
                md.append(f"| {label} | {any_r['n_truth']} | "
                          f"{any_r['chance']:.3f} | " +
                          " | ".join(f"{cells[d]['recall']:.2f}"
                                     if d in cells else "" for d in dets) + " |")
            md.append("")
    return "\n".join(md) + "\n"


# ---------------------------------------------------------------- driver

def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck()
    lib.register_eval_views(con, args.eval)
    truth = con.execute("SELECT * FROM eval_truth").to_arrow_table().to_pylist()
    day = min(t["start_ts"] for t in truth).astimezone(_dt.timezone.utc).date()
    fit_days = _fit_days(con, day, args.fit_days)
    if not fit_days:
        raise SystemExit(f"[baselines] no recorded days before {day}")
    fit_pred = _days_pred(fit_days)
    print(f"[baselines] day {day}, fit {fit_days[0]}..{fit_days[-1]}",
          file=sys.stderr)

    fit = _source_features(con, fit_pred)
    d = _source_features(con, f"dt = DATE '{day}'")
    new24 = _new_port_24(con, fit_pred, day, d["src_ip"])
    src_scores = source_scores(fit, d, new24, args.seed)
    rows = eval_source(args.eval, d["src_ip"], src_scores, truth,
                       args.source_k, args.seed)
    from bench import harness2
    harness2.write_ranks("baselines", args.eval, harness2.truth_ranks(
        args.eval, day, d["src_ip"], src_scores, truth, args.seed))

    days = fit_days + [day]
    ser = _minute_series(con, days, _days_pred(days))
    masked = interval_mask(ser["minute"], lib.load_sensor_mask())
    # Fit minutes come from the recorded fit days only, minus the mask, so
    # unrecorded calendar days between them never read as silent minutes.
    mday = np.array([_dt.datetime.fromtimestamp(m, _dt.timezone.utc).date()
                     for m in ser["minute"][::1440]])
    mday = np.repeat(mday, 1440)[:len(ser["minute"])]
    fit_set = set(fit_days)
    in_fit = np.array([x in fit_set for x in mday])
    in_day = mday == day
    use = np.where(in_fit | in_day)[0]
    fit_idx = np.where(in_fit & ~masked)[0]
    day_idx = np.where(in_day)[0]
    valid = ~masked[day_idx]
    n_fit_hours = max(1, len(fit_idx) // 60)
    ph = _port_hour_z(con, fit_pred, day, n_fit_hours)
    con.close()
    g_scores = global_scores(ser, use, masked, fit_idx, day_idx, ph, args.seed)
    rows += eval_global(args.eval, ser["minute"][day_idx], valid, g_scores,
                        truth, args.global_k, args.max_global_window_min,
                        args.seed)

    md = _markdown(rows, args.eval, day, fit_days, len(d["src_ip"]),
                   int(valid.sum()))
    return lib.Report(name="baselines", rows=rows, schema=RESULT_SCHEMA,
                      markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--eval", required=True, metavar="NAME",
                    help="adversarysim --inject set to score against.")
    ap.add_argument("--fit-days", type=int, default=7)
    ap.add_argument("--source-k", type=int, nargs="+", default=[10, 100, 1000])
    ap.add_argument("--global-k", type=int, nargs="+", default=[10, 60])
    ap.add_argument("--max-global-window-min", type=int, default=120)
    ap.add_argument("--seed", type=int, default=20261023)
    args = ap.parse_args()
    # One file per injection set, so detectors compare on the same set.
    paths = run(args).write(suffix=args.eval)
    print(f"[baselines] wrote {paths['parquet']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

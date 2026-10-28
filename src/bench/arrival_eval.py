#!/usr/bin/env python3
"""
bench/arrival_eval — Phase 2 global arrival detectors and their gate.

Reads output/reports/arrival/arrival_series.parquet (bench/arrival_series)
and scores every minute with the detectors of ARCHITECTURE §9.6:

  ngrc_htm       primary: NG-RC (2 lags, linear + quadratic, daily phase)
                 ridge readout -> per-column residual -> HTM likelihood
                 (10-min mean vs the fit window) -> Benjamini-Hochberg
  ar_htm         twin: the same with linear terms only
  ngrc_spot      twin: the same residual, SPOT/EVT tail in place of HTM
  untrained_htm  untrained copy: hour-of-day mean of the fit window
  tail5x         baseline: new_src / detect_coordination tail median
  stl_z          baseline: bench/baselines STL residual z
  hawkes         reported: discrete Hawkes (Poisson INGARCH) on new_src
  midas_r        reported: MIDAS-R (Bhatia et al. 2020) on (source /24,
                 destination port) edges, one tick per unmasked minute
  hst            reported: river Half-Space Trees on the minute vector
  bocpd          reported: Adams-MacKay BOCPD on 10-minute means of the
                 signed ngrc residual; score = P(change in the last hour)
  ngrc_bocpd     reported: ngrc_htm, but a day keeps the weights of the day
                 before when BOCPD saw a change in the 24 h before 00:00
  deeplog        reported: the DeepLog (Du et al. 2017) parameter-value
                 model: LSTM next-vector prediction, Gaussian error tail per
                 column, Benjamini-Hochberg.  The log-key model has no keys
                 at the minute level, so it is not used here.
  markov         reported: first-order Markov chain of the packet tokens of
                 each source, token = (proto, tcp_flags, dst_port); score =
                 mean surprise (bits) of the minute's transitions
  som            reported: batch self-organizing map (12 x 12) of the
                 standardized minute vector; score = quantization error /
                 the median error of the fit window
  rrcf           reported: Robust Random Cut Forest (Guha et al. 2016),
                 40 trees of 256 fit-window minutes built each day; score
                 = mean CoDisp of the minute inserted into each tree
  cms            reported: Count-Min sketch of destination ports with two
                 leaky (exponentially decayed) copies, tau 10 min and 1 day;
                 score = largest fast/slow rate ratio of the minute (bits)
  hll            reported: HyperLogLog (DuckDB approx_count_distinct)
                 distinct ports of each source per 10-minute block; score =
                 robust z of log1p(largest fan-out) against the fit window

Every fit for day D uses only the last FIT_DAYS recorded days before D
that come after the last long mask (>= 1 day).  The detectors keep no
other state across days except the HTM/SPOT score history (previous
HIST_DAYS recorded days).  So ``--start`` can begin anywhere: the dev run
(``--mode dev``) starts 2024-07-25 and never touches test period 1.

Modes:
  dev   --start 2024-07-25 --end 2025-11-10.  One-step error for each
        ridge value, alarm counts at fixed daily rates.  No event windows.
  gate  2024-02-08 to 2026-05-29; the §9.6 gate (theta*, alarm episodes,
        FA/yr) on the two §9.6 test periods.
  full  every day of the series; the same gate with every scored minute
        as a test minute, the FA/yr of each calendar year, and the events
        each detector finds at fixed alarm budgets (1 and 10 alarm
        minutes per day).

Output: output/reports/arrival_eval/arrival_eval_<mode>.{parquet,md}
        plus arrival_scores_<mode>.parquet (one row per scored minute)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import math
import sys
import time
from collections import deque
from contextlib import contextmanager, nullcontext
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib
from bench import arrival_series as ars
from bench import baselines as bl

SERIES = lib.REPORTS / "arrival" / "arrival_series.parquet"
OUT = lib.REPORTS / "arrival_eval"

FIT_DAYS = 7          # recorded days in the fit window
MIN_FIT_DAYS = 3      # fewer -> no score that day
HIST_DAYS = 2         # recorded days of score history for HTM / SPOT
REC_MIN = 720         # unmasked minutes that make a recorded day
LONG_MASK_S = 86400   # a mask this long starts a new segment
WARM_MIN = 60         # minutes after a mask end with no score
SHORT_WIN = 10        # HTM short window (minutes)
SPOT_Q0 = 0.98        # SPOT initial threshold quantile
LAGS = 2
CLIP = 3.0            # standardized NG-RC inputs are clipped to +/- CLIP
RIDGES = (1e-3, 1e-2, 1e-1, 1.0)   # per fit row (lambda * n); bias unpenalized
EPISODE_JOIN_MIN = 30
EVENT_GUARD_S = 6 * 3600
MIDAS_ROWS, MIDAS_COLS = 2, 1024   # the authors' default sketch size
MIDAS_FACTOR = 0.5                 # MIDAS-R decay of the current counts
HST_TREES, HST_HEIGHT, HST_WINDOW = 10, 8, 250   # river defaults
BOCPD_BLOCK = 10                   # minutes per BOCPD observation
BOCPD_HAZARD = 1.0 / (144 * 7)     # one change a week a priori
BOCPD_RMAX = 144 * 7               # run lengths kept (one week of blocks)
BOCPD_RECENT = 6                   # score = P(run length < 6 blocks = 1 h)
BOCPD_CP = 0.5                     # a change, for the refit stop
BOCPD_HOLD_S = 86400               # refit stop after a change
BOCPD_PRIOR = (0.0, 1.0, 1.0, 0.01)  # Normal-Gamma mu0, kappa0, alpha0, beta0
AGG_COLS = 7                       # pkts .. no_port: the BOCPD signal
DL_HIST, DL_HIDDEN, DL_LAYERS = 10, 64, 2   # DeepLog: window h, LSTM size
DL_EPOCHS_FIRST, DL_EPOCHS_DAY = 5, 1
DL_BATCH, DL_LR, DL_CLIP = 256, 1e-3, 5.0
MK_BACKOFF = 1.0                   # weight of the token prior in P(b|a)
SOM_SIDE = 12                      # SOM_SIDE x SOM_SIDE cells
SOM_NEW = (10, 4.0, 1.0)           # new map: batch steps, sigma start, end
SOM_DAY = (2, 1.0, 1.0)            # each day after: warm start
RRCF_TREES, RRCF_SAMPLE = 40, 256
CMS_ROWS, CMS_COLS = 4, 2048
CMS_TAU = (10.0, 1440.0)           # fast / slow decay constants (minutes)
HLL_BLOCK = 10                     # minutes per fan-out block

COLS = [c for c in ars.COUNT_COLS] + ["syn_share"]
GATE = ("ngrc_htm", "ar_htm", "untrained_htm", "tail5x", "stl_z")
REPORTED = ("ngrc_spot", "hawkes", "midas_r", "hst", "bocpd", "ngrc_bocpd",
            "deeplog", "markov", "som", "rrcf", "cms", "hll")
DETECTORS = GATE[:1] + ("ar_htm", "ngrc_spot", "untrained_htm",
                        "tail5x", "stl_z", "hawkes", "midas_r", "hst",
                        "bocpd", "ngrc_bocpd", "deeplog", "markov", "som",
                        "rrcf", "cms", "hll")
EXTERNAL = ("midas_r", "hst", "deeplog", "markov", "som", "rrcf", "cms",
            "hll")

PERIODS = {   # ARCHITECTURE §9.6, inclusive UTC days
    "test1": (_dt.date(2024, 2, 22), _dt.date(2024, 7, 31)),
    "dev":   (_dt.date(2024, 8, 1), _dt.date(2025, 11, 10)),
    "test2": (_dt.date(2026, 2, 6), _dt.date(2026, 5, 29)),
}
EVENTS = {
    "E1": ("2024-06-24T14:30:00+00:00", "2024-06-24T14:50:00+00:00"),
    "E2": ("2026-04-27T00:00:00+00:00", "2026-05-02T00:00:00+00:00"),
    "E3": ("2026-05-19T00:00:00+00:00", "2026-05-20T00:00:00+00:00"),
}

RESULT_SCHEMA = pa.schema([
    ("mode",       pa.string()),
    ("detector",   pa.string()),
    ("metric",     pa.string()),
    ("value",      pa.float64()),
])


# ---------------------------------------------------------------- pure helpers

class Clock:
    """Exclusive wall and CPU seconds per name (bench/efficiency.py).

    A nested ``time()`` pauses the outer name, so each second goes to one
    name only."""

    def __init__(self):
        self.wall: dict[str, float] = {}
        self.cpu: dict[str, float] = {}
        self._stack: list[str] = []
        self._w = self._c = 0.0

    def _charge(self) -> None:
        w, c = time.perf_counter(), time.process_time()
        if self._stack:
            k = self._stack[-1]
            self.wall[k] = self.wall.get(k, 0.0) + w - self._w
            self.cpu[k] = self.cpu.get(k, 0.0) + c - self._c
        self._w, self._c = w, c

    @contextmanager
    def time(self, name: str):
        self._charge()
        self._stack.append(name)
        try:
            yield
        finally:
            self._charge()
            self._stack.pop()


def bh_log_min(logp: np.ndarray) -> np.ndarray:
    """Smallest Benjamini-Hochberg adjusted p-value of each row, as -log10.
    ``logp`` is (n, C) natural-log p-values."""
    c = logp.shape[1]
    s = np.sort(logp, axis=1) + np.log(c / np.arange(1, c + 1))
    return -np.minimum(s.min(axis=1), 0.0) / math.log(10)


def quad_features(lin: np.ndarray) -> np.ndarray:
    """Unique pairwise products (incl. squares) of the linear NG-RC vector."""
    i, j = np.triu_indices(lin.shape[1])
    return lin[:, i] * lin[:, j]


def rolling_mean(x: np.ndarray, ok: np.ndarray, w: int) -> np.ndarray:
    """Mean of the last ``w`` rows of ``x`` inside runs of ``ok`` (NaN where
    the run is shorter than ``w``).  Rows are minutes of one day plus the
    tail of the day before, so a run never spans a reset."""
    out = np.full_like(x, np.nan)
    run = 0
    cs = np.vstack([np.zeros((1, x.shape[1])), np.cumsum(
        np.where(ok[:, None], x, 0.0), axis=0)])
    for t in range(len(x)):
        run = run + 1 if ok[t] else 0
        if run >= w:
            out[t] = (cs[t + 1] - cs[t + 1 - w]) / w
    return out


def episodes(alarm_ts: np.ndarray, join_s: int) -> list[tuple[float, float]]:
    """Join sorted alarm minute starts into (start, end) episodes."""
    out: list[list[float]] = []
    for t in alarm_ts:
        if out and t - out[-1][1] <= join_s:
            out[-1][1] = t
        else:
            out.append([t, t])
    return [(a, b + 60) for a, b in out]


def gate_metrics(score: np.ndarray, ts: np.ndarray, test: np.ndarray,
                 events: dict[str, tuple[float, float]]) -> dict:
    """theta* = smallest of the per-event max scores; FA/yr = episodes at
    theta* that miss every event window (+/- guard), per test year."""
    ev_max = {}
    for k, (a, b) in events.items():
        w = (ts + 60 > a) & (ts < b) & np.isfinite(score)
        ev_max[k] = float(score[w].max()) if w.any() else -np.inf
    # an event with no score (inside the warm-up after a long mask, for
    # example) cannot set theta*; it stays in the guard windows
    scored = [v for v in ev_max.values() if np.isfinite(v)]
    theta = min(scored) if scored else np.inf
    sel = test & np.isfinite(score) & (score >= theta)
    eps = episodes(np.sort(ts[sel]), EPISODE_JOIN_MIN * 60)
    fa = [e for e in eps if not any(e[1] > a - EVENT_GUARD_S and
                                    e[0] < b + EVENT_GUARD_S
                                    for a, b in events.values())]
    years = test.sum() / 525_600
    out = {"theta": theta, "episodes": len(eps), "fa": len(fa),
           "events_scored": float(len(scored)),
           "fa_per_year": len(fa) / years if years else math.nan,
           "test_minutes": float(test.sum())}
    out.update({f"max_{k}": v for k, v in ev_max.items()})
    return out


# ---------------------------------------------------------------- data

def load_grid(start: _dt.date, end: _dt.date) -> dict:
    t0 = _dt.datetime.combine(start, _dt.time(), _dt.timezone.utc).timestamp()
    n_days = (end - start).days + 1
    n = n_days * 1440
    tab = pq.read_table(SERIES)
    ep = tab["minute"].cast(pa.int64()).to_numpy() / 1e6
    idx = ((ep - t0) // 60).astype(np.int64)
    keep = (idx >= 0) & (idx < n)
    raw = np.zeros((n, len(COLS)))
    for j, c in enumerate(COLS):
        raw[idx[keep], j] = tab[c].to_numpy(zero_copy_only=False)[keep]
    minute = t0 + 60.0 * np.arange(n)
    mask_iv = lib.load_sensor_mask()
    masked = bl.interval_mask(minute, mask_iv)
    # minutes since the last mask end (any length), and the start of the
    # current segment (end of the last mask of >= LONG_MASK_S)
    since = np.full(n, 10**9, dtype=np.int64)
    seg_start = np.full(n, -np.inf)
    for s, e, _ in mask_iv:
        s_ep, e_ep = s.timestamp(), e.timestamp()
        i = int(math.ceil((e_ep - t0) / 60))
        if 0 <= i < n:
            since[i:] = np.minimum(since[i:], np.arange(n - i))
        if e_ep - s_ep >= LONG_MASK_S:
            seg_start[minute >= e_ep] = np.maximum(seg_start[minute >= e_ep], e_ep)
    x = np.log1p(raw)
    x[:, COLS.index("syn_share")] = raw[:, COLS.index("syn_share")]
    return {"t0": t0, "n_days": n_days, "minute": minute, "raw": raw,
            "x": x, "masked": masked, "since": since, "seg_start": seg_start}


# ---------------------------------------------------------------- detectors

class Window:
    """Per-day sufficient statistics of the last FIT_DAYS recorded days."""

    def __init__(self, maxlen: int):
        self.days: deque = deque(maxlen=maxlen)

    def push(self, stats: dict) -> None:
        self.days.append(stats)

    def usable(self, seg: float) -> list[dict]:
        return [d for d in self.days if d["day_ts"] >= seg]


def _ridge(g: np.ndarray, b: np.ndarray, lam: float, n: int) -> np.ndarray:
    """Ridge with ``lam`` per fit row; column 0 (the bias) is not shrunk,
    or a large ridge drags log1p(pkts) ~ 7 toward zero."""
    pen = np.full(len(g), lam * n)
    pen[0] = 0.0
    return np.linalg.solve(g + np.diag(pen), b)


def htm_logp(m: np.ndarray, hist: np.ndarray) -> np.ndarray:
    """HTM anomaly likelihood tail: log Q((m - mu) / sd) per column, with
    mu/sd of the raw scores in ``hist`` (the previous recorded days)."""
    from scipy.special import log_ndtr
    mu = np.nanmean(hist, axis=0)
    sd = np.maximum(np.nanstd(hist, axis=0), 1e-6)
    return log_ndtr(-(m - mu) / sd)


def spot_logp(m: np.ndarray, hist: np.ndarray) -> np.ndarray:
    """SPOT tail: GPD fit to the peaks of ``hist`` (short-window means of
    the previous recorded days) over its SPOT_Q0 quantile; empirical
    survival below the threshold."""
    from scipy.stats import genpareto
    out = np.zeros_like(m)
    for j in range(m.shape[1]):
        h = hist[:, j][np.isfinite(hist[:, j])]
        col = m[:, j]
        if len(h) < 100:
            out[:, j] = np.nan
            continue
        h.sort()
        u = np.quantile(h, SPOT_Q0)
        peaks = h[h > u] - u
        surv = 1.0 - np.searchsorted(h, col, side="left") / len(h)
        lp = np.log(np.maximum(surv, 1.0 / len(h)))
        if len(peaks) >= 10 and peaks.std() > 0:
            c, _, sc = genpareto.fit(peaks, floc=0)
            above = col > u
            lp[above] = (math.log(len(peaks) / len(h))
                         + genpareto.logsf(col[above] - u, c, 0, sc))
        lp[~np.isfinite(col)] = np.nan
        out[:, j] = lp
    return out


class Bocpd:
    """Adams & MacKay (2007) online change-point detection, constant
    hazard, Normal-Gamma model (Student-t predictive), run lengths
    truncated at BOCPD_RMAX."""

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        mu0, k0, a0, b0 = BOCPD_PRIOR
        self.r = np.array([1.0])
        self.mu, self.k = np.array([mu0]), np.array([k0])
        self.a, self.b = np.array([a0]), np.array([b0])

    def update(self, xv: float) -> float:
        from scipy.stats import t as student_t
        mu0, k0, a0, b0 = BOCPD_PRIOR
        scale = np.sqrt(self.b * (self.k + 1) / (self.a * self.k))
        pred = student_t.pdf(xv, 2 * self.a, loc=self.mu, scale=scale)
        growth = self.r * pred * (1 - BOCPD_HAZARD)
        cp = float((self.r * pred * BOCPD_HAZARD).sum())
        r = np.concatenate([[cp], growth])
        tot = r.sum()
        r = r / tot if tot > 0 else np.eye(1, len(r))[0]
        mu = np.concatenate([[mu0], (self.k * self.mu + xv) / (self.k + 1)])
        b = np.concatenate([[b0], self.b + self.k * (xv - self.mu) ** 2
                            / (2 * (self.k + 1))])
        k = np.concatenate([[k0], self.k + 1])
        a = np.concatenate([[a0], self.a + 0.5])
        keep = slice(0, BOCPD_RMAX)
        self.r, self.mu, self.k, self.a, self.b = (r[keep], mu[keep], k[keep],
                                                   a[keep], b[keep])
        self.r = self.r / self.r.sum()
        return float(self.r[:BOCPD_RECENT].sum())


def run_detectors(g: dict, ridges=RIDGES, ridge_ngrc: float = 1.0,
                  ridge_ar: float = 1e-1, log=sys.stderr,
                  clock: Clock | None = None) -> dict:
    """``clock`` (bench/efficiency.py) gets the seconds of each detector;
    ``inputs`` is the shared lag matrix, ``diagnostic`` the ridge sweep."""
    T = clock.time if clock is not None else (lambda name: nullcontext())
    n, C = g["x"].shape
    x, minute = g["x"], g["minute"]
    valid = ~g["masked"]
    ok = valid & (g["since"] >= WARM_MIN)
    for k in range(1, LAGS + 1):
        ok[k:] &= valid[:-k]
    ok[:LAGS] = False
    hod = ((minute // 3600) % 24).astype(int)
    with T("inputs"):
        phase = np.stack([np.sin(2 * np.pi * hod / 24),
                          np.cos(2 * np.pi * hod / 24)], axis=1)
        lin_all = np.hstack([np.roll(x, k, axis=0) for k in range(1, LAGS + 1)])

        # standardize the NG-RC inputs on the first recorded days of the run
        first = np.where(ok)[0][:3 * 1440]
        mu_x, sd_x = lin_all[first].mean(0), lin_all[first].std(0) + 1e-6

    scores = {d: np.full(n, np.nan) for d in DETECTORS if d not in EXTERNAL}
    sq_err = {(m, lam): [0.0, 0] for m in ("ngrc", "ar") for lam in ridges}
    win = {"ngrc": Window(FIT_DAYS), "ar": Window(FIT_DAYS),
           "hour": Window(FIT_DAYS)}
    hist = {k: Window(HIST_DAYS) for k in ("ngrc", "ar", "untr", "spot",
                                            "ngrcb")}
    bocpd = Bocpd()
    last_cp = -np.inf
    held_w, held_seg = None, None

    # tail5x: the detect_coordination rule (median of the top-5000 minutes
    # with new_src >= 5, over the whole corpus, as that module computes it)
    ns = g["raw"][:, COLS.index("new_src")]
    with T("tail5x"):
        full = pq.read_table(SERIES, columns=["new_src"])["new_src"].to_numpy()
        top = np.sort(full[full >= 5])[::-1][:5000]
        scores["tail5x"] = ns / max(float(np.median(top)) if len(top) else 1.0, 1.0)

    ser = {"minute": minute, "pkts": g["raw"][:, COLS.index("pkts")],
           "n_src": g["raw"][:, COLS.index("n_src")],
           "n_ports": g["raw"][:, COLS.index("n_ports")],
           "new_src": ns, "syn_share": g["raw"][:, COLS.index("syn_share")]}
    rec_days: deque = deque(maxlen=FIT_DAYS)
    with T("hawkes"):
        hawkes_s = _hawkes_ewma(ns, valid)
    t_start = time.time()
    names = {"ngrc": "ngrc_htm", "ar": "ar_htm", "untr": "untrained_htm",
             "ngrcb": "ngrc_bocpd"}

    for d in range(g["n_days"]):
        a, b = d * 1440, (d + 1) * 1440
        day_ts = minute[a]
        seg = g["seg_start"][a]
        rows = np.arange(a, b)
        okd = ok[a:b]
        with T("inputs"):
            lin = np.clip((lin_all[a:b] - mu_x) / sd_x, -CLIP, CLIP)
            phi_lin = np.hstack([np.ones((1440, 1)), lin, phase[a:b]])
        with T("ngrc_htm"):
            phi_q = np.hstack([phi_lin, quad_features(lin)])
        y = x[a:b]
        fit_n = win["ngrc"].usable(seg)
        scored = len(fit_n) >= MIN_FIT_DAYS

        if scored:
            with T("ngrc_htm"):
                gq = sum(w["g"] for w in fit_n); bq = sum(w["b"] for w in fit_n)
                nq = sum(w["cnt"] for w in fit_n)
            with T("ar_htm"):
                ar_n = win["ar"].usable(seg)
                gl = sum(w["g"] for w in ar_n); blin = sum(w["b"] for w in ar_n)
                nl = sum(w["cnt"] for w in ar_n)
            with T("diagnostic"):
                for (mname, lam), acc in sq_err.items():
                    ph, gg, bb, nn = ((phi_q, gq, bq, nq) if mname == "ngrc"
                                      else (phi_lin, gl, blin, nl))
                    e = y[okd] - ph[okd] @ _ridge(gg, bb, lam, nn)
                    acc[0] += float((e ** 2).sum()); acc[1] += e.size
            with T("ngrc_htm"):
                w_q = _ridge(gq, bq, ridge_ngrc, nq)
                resid = {"ngrc": y - phi_q @ w_q}
            with T("ngrc_bocpd"):
                if held_seg != seg:
                    held_w = None
                w_b = (held_w if held_w is not None and day_ts - last_cp <= BOCPD_HOLD_S
                       else w_q)
                held_w, held_seg = w_b, seg
                resid["ngrcb"] = y - phi_q @ w_b
            with T("ar_htm"):
                resid["ar"] = y - phi_lin @ _ridge(gl, blin, ridge_ar, nl)
            # BOCPD on 10-minute means of the signed ngrc residual of the
            # aggregate columns; each block's score goes to the next block.
            # The 00:00 refit moves the residual level, so BOCPD restarts
            # with each day (and at each mask end); the first BOCPD_RECENT
            # blocks after a restart carry no score (P(r < 6) is 1 there).
            with T("bocpd"):
                bocpd.reset(); n_upd = 0; bocpd_pending = np.nan
                sig = resid["ngrc"][:, :AGG_COLS].mean(1)
                since_d = g["since"][a:b]
                for blk in range(0, 1440, BOCPD_BLOCK):
                    sl = slice(blk, blk + BOCPD_BLOCK)
                    scores["bocpd"][a + blk:a + blk + BOCPD_BLOCK] = bocpd_pending
                    if (since_d[sl] == 0).any():
                        bocpd.reset(); n_upd = 0; bocpd_pending = np.nan
                    okb = okd[sl]
                    if okb.sum() >= BOCPD_BLOCK // 2:
                        p_recent = bocpd.update(float(sig[sl][okb].mean()))
                        n_upd += 1
                        bocpd_pending = p_recent if n_upd > BOCPD_RECENT else np.nan
                        if n_upd > BOCPD_RECENT and p_recent >= BOCPD_CP:
                            last_cp = minute[a + blk] + 60 * BOCPD_BLOCK
            with T("untrained_htm"):
                hs = win["hour"].usable(seg)
                hsum = sum(w["hsum"] for w in hs); hcnt = sum(w["hcnt"] for w in hs)
                resid["untr"] = y - hsum[hod[a:b]] / np.maximum(hcnt[hod[a:b]], 1)[:, None]
            for k in ("ngrc", "ar", "untr", "ngrcb"):
                # raw anomaly = |residual|; the HTM step standardizes each
                # column against its own history, so no residual scale here
                with T(names[k]):
                    s = np.abs(resid[k])
                    s[~okd] = np.nan
                    m = rolling_mean(np.nan_to_num(s), okd, SHORT_WIN)
                    hh = hist[k].usable(seg)
                    if len(hh) >= HIST_DAYS:
                        hcat = np.vstack([h["s"] for h in hh])
                        lp = htm_logp(m, hcat)
                        sc = bh_log_min(np.nan_to_num(lp, nan=0.0))
                        sc[~np.isfinite(m).all(1)] = np.nan
                        scores[names[k]][a:b] = sc
                        if k == "ngrc":
                            with T("ngrc_spot"):
                                mcat = np.vstack([h["m"] for h in hist["spot"].usable(seg)])
                                lsp = spot_logp(m, mcat)
                                sp = bh_log_min(np.nan_to_num(lsp, nan=0.0))
                                sp[~np.isfinite(m).all(1) | ~np.isfinite(lsp).all(1)] = np.nan
                                scores["ngrc_spot"][a:b] = sp
                    hist[k].push({"day_ts": day_ts, "s": s})
                    if k == "ngrc":
                        hist["spot"].push({"day_ts": day_ts, "m": m})

            # stl_z on the same fit days (bench/baselines definition)
            with T("inputs"):
                fit_rows = np.concatenate([np.arange(r, r + 1440) for r in rec_days
                                           if minute[r] >= seg] or [np.arange(0)])
            if len(fit_rows) >= MIN_FIT_DAYS * 1440:
                with T("stl_z"):
                    use = np.concatenate([fit_rows, rows])
                    fit_idx = fit_rows[valid[fit_rows]]
                    gs = bl.global_scores(ser, use, g["masked"], fit_idx, rows,
                                          np.zeros(24), 0)
                    st = gs["stl_z"].astype(float)
                    st[~okd] = np.nan
                    scores["stl_z"][a:b] = st
            # hawkes on new_src, fit on the same days
            with T("hawkes"):
                scores["hawkes"][a:b] = _hawkes_day(ns, hawkes_s, hod, fit_rows,
                                                    ok, rows)
        # tail5x is global; restrict it to the minutes the others can score
        scores["tail5x"][a:b][~okd] = np.nan

        # push this day's statistics if it is a recorded day
        if valid[a:b].sum() >= REC_MIN and okd.sum() > 0:
            yo = y[okd]
            st = {"day_ts": day_ts, "cnt": int(okd.sum())}
            with T("ngrc_htm"):
                pq_ = phi_q[okd]
                win["ngrc"].push({**st, "g": pq_.T @ pq_, "b": pq_.T @ yo})
            with T("ar_htm"):
                pl_ = phi_lin[okd]
                win["ar"].push({**st, "g": pl_.T @ pl_, "b": pl_.T @ yo})
            with T("untrained_htm"):
                hsum = np.zeros((24, C)); hcnt = np.zeros(24)
                np.add.at(hsum, hod[a:b][okd], yo); np.add.at(hcnt, hod[a:b][okd], 1)
                win["hour"].push({**st, "hsum": hsum, "hcnt": hcnt})
            rec_days.append(a)
        if (d + 1) % 50 == 0:
            print(f"[arrival_eval] day {d + 1}/{g['n_days']} "
                  f"{time.time() - t_start:.0f}s", file=log)
    for name in scores:
        scores[name][~ok] = np.nan
    return {"scores": scores, "ok": ok,
            "mse": {lam: s / max(c, 1) for lam, (s, c) in sq_err.items()}}


def _hawkes_ewma(ns: np.ndarray, valid: np.ndarray,
                 betas=(0.5, 0.7, 0.8, 0.9, 0.95, 0.98)) -> dict:
    """S_beta[t] = (1-beta) * sum_k beta^(k-1) N[t-k], reset at masked
    minutes (the discrete exponential kernel of a Hawkes process)."""
    from scipy.signal import lfilter
    out = {}
    n0 = np.where(valid, ns, 0.0)
    for bt in betas:
        s = lfilter([1 - bt], [1, -bt], n0)
        s = np.concatenate([[0.0], s[:-1]])      # strictly the past
        out[bt] = s
    return out


def _hawkes_day(ns, hs, hod, fit_rows, ok, rows,
                alphas=(0.0, 0.2, 0.4, 0.6, 0.8, 0.9)) -> np.ndarray:
    """lambda_t = (1 - a) mu_h + a S_beta[t]; grid MLE on the fit rows;
    score = -log10 Poisson P(N >= n)."""
    from scipy.stats import poisson
    out = np.full(len(rows), np.nan)
    fr = fit_rows[ok[fit_rows]]
    if len(fr) < MIN_FIT_DAYS * 720:
        return out
    mu_h = np.zeros(24)
    np.add.at(mu_h, hod[fr], ns[fr])
    mu_h /= np.maximum(np.bincount(hod[fr], minlength=24), 1)
    best, ll_best = None, -np.inf
    for bt, s in hs.items():
        for al in alphas:
            lam = np.maximum((1 - al) * mu_h[hod[fr]] + al * s[fr], 1e-3)
            ll = float((ns[fr] * np.log(lam) - lam).sum())
            if ll > ll_best:
                best, ll_best = (bt, al), ll
    bt, al = best
    lam = np.maximum((1 - al) * mu_h[hod[rows]] + al * hs[bt][rows], 1e-3)
    lsf = poisson.logsf(ns[rows] - 1, lam)
    out = -lsf / math.log(10)
    out[~ok[rows]] = np.nan
    return out


# ---------------------------------------------------------------- MIDAS-R

_P = 2147483647            # Mersenne prime for the sketch hashes


def _midas_hashes(seed: int = 7) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    return (rng.integers(1, _P, size=MIDAS_ROWS, dtype=np.int64),
            rng.integers(0, _P, size=MIDAS_ROWS, dtype=np.int64))


def _midas_kernel():
    from numba import njit

    @njit(cache=True)
    def score(a, s, t):
        if s == 0.0 or t - 1.0 <= 0.0:
            return 0.0
        d = (a - s / t) * t
        return d * d / (s * (t - 1.0))

    @njit(cache=True)
    def day(rec_min, u, v, c, n_min, valid, reset_cur, reset_all,
            cur, tot, ha, hb, t_tick, out):
        """One day of MIDAS-R.  ``cur``/``tot`` are (3, rows, cols) sketches
        for edge, source and destination.  All records of a minute update
        the sketches first; then each record gets its score with the
        minute's final counts (end-of-tick form of the per-edge update)."""
        rows, cols = cur.shape[1], cur.shape[2]
        p = 0
        nrec = len(rec_min)
        keys = np.empty(3, dtype=np.int64)
        for j in range(n_min):
            if reset_all[j]:
                cur[:] = 0.0
                tot[:] = 0.0
                t_tick[0] = 0.0
            elif reset_cur[j]:
                cur[:] = 0.0
            q = p
            while q < nrec and rec_min[q] == j:
                q += 1
            if not valid[j]:
                p = q
                continue
            t_tick[0] += 1.0
            cur *= 0.5
            for i in range(p, q):
                keys[0] = (u[i] * 70001 + v[i]) % 2147483647
                keys[1] = u[i] % 2147483647
                keys[2] = (v[i] + 1000003) % 2147483647
                for k in range(3):
                    for r in range(rows):
                        h = ((ha[r] * keys[k] + hb[r]) % 2147483647) % cols
                        cur[k, r, h] += c[i]
                        tot[k, r, h] += c[i]
            best = 0.0
            for i in range(p, q):
                keys[0] = (u[i] * 70001 + v[i]) % 2147483647
                keys[1] = u[i] % 2147483647
                keys[2] = (v[i] + 1000003) % 2147483647
                for k in range(3):
                    a = 1e300
                    s = 1e300
                    for r in range(rows):
                        h = ((ha[r] * keys[k] + hb[r]) % 2147483647) % cols
                        a = min(a, cur[k, r, h])
                        s = min(s, tot[k, r, h])
                    best = max(best, score(a, s, t_tick[0]))
            out[j] = best
            p = q
    return day


def midas_scores(g: dict, start: _dt.date, ok: np.ndarray,
                 log=sys.stderr) -> np.ndarray:
    """MIDAS-R minute score = the largest edge / source / destination score
    of the minute.  An edge is (source /24, destination port); a packet is
    one edge occurrence.  The current counts reset at each mask end and
    all counts reset at the start of a segment (a mask of >= 1 day)."""
    assert MIDAS_FACTOR == 0.5     # the kernel decays by 0.5 per tick
    kern = _midas_kernel()
    n = len(g["minute"])
    out = np.full(n, np.nan)
    valid = ~g["masked"]
    reset_cur = g["since"] == 0
    seg = g["seg_start"]
    reset_all = np.zeros(n, dtype=bool)
    reset_all[1:] = seg[1:] != seg[:-1]
    cur = np.zeros((3, MIDAS_ROWS, MIDAS_COLS))
    tot = np.zeros_like(cur)
    ha, hb = _midas_hashes()
    t_tick = np.zeros(1)
    con = lib.duck()
    lib.register_views(con)
    t0 = time.time()
    for d in range(g["n_days"]):
        day = start + _dt.timedelta(days=d)
        a = d * 1440
        rec = con.execute(f"""
            SELECT ((epoch(date_trunc('minute', ts))::BIGINT - {int(g['minute'][a])}) // 60)::BIGINT,
                   (hash({ars.prefix_sql()}) % 2147483647)::BIGINT,
                   coalesce(dst_port::BIGINT, 65536 + coalesce(proto, 0)::BIGINT),
                   count(*)::DOUBLE
            FROM packets WHERE dt = DATE '{day}' AND {ars.NOT_NTP}
            GROUP BY ALL ORDER BY 1
        """).fetchnumpy()
        cols = list(rec.values())
        day_out = np.zeros(1440)
        kern(np.asarray(cols[0], dtype=np.int64), np.asarray(cols[1], dtype=np.int64),
             np.asarray(cols[2], dtype=np.int64), np.asarray(cols[3], dtype=np.float64),
             1440, valid[a:a + 1440], reset_cur[a:a + 1440], reset_all[a:a + 1440],
             cur, tot, ha, hb, t_tick, day_out)
        out[a:a + 1440] = day_out
        if (d + 1) % 50 == 0:
            print(f"[arrival_eval] midas day {d + 1}/{g['n_days']} "
                  f"{time.time() - t0:.0f}s", file=log)
    con.close()
    out[~ok] = np.nan
    return out


# ---------------------------------------------------------------- Half-Space Trees

def hst_scores(g: dict, ok: np.ndarray, log=sys.stderr) -> np.ndarray:
    """river Half-Space Trees, score before learn for each unmasked minute.
    The feature limits come from the first 3 recorded days of the run (the
    trees need a fixed box); a new segment starts a new model."""
    from river import anomaly
    x = g["x"]
    n = len(x)
    valid = ~g["masked"]
    seg = g["seg_start"]
    first = np.where(valid)[0][:3 * 1440]
    lo, hi = x[first].min(0), x[first].max(0)
    span = np.maximum(hi - lo, 1e-6)
    limits = {c: (float(lo[j] - 0.5 * span[j]), float(hi[j] + 0.5 * span[j]))
              for j, c in enumerate(COLS)}

    def new():
        return anomaly.HalfSpaceTrees(n_trees=HST_TREES, height=HST_HEIGHT,
                                      window_size=HST_WINDOW, limits=limits,
                                      seed=42)
    model = new()
    out = np.full(n, np.nan)
    t0 = time.time()
    for i in range(n):
        if i and seg[i] != seg[i - 1]:
            model = new()
        if not valid[i]:
            continue
        f = dict(zip(COLS, x[i].tolist()))
        if ok[i]:
            out[i] = model.score_one(f)
        model.learn_one(f)
        if (i + 1) % 200_000 == 0:
            print(f"[arrival_eval] hst {i + 1}/{n} {time.time() - t0:.0f}s",
                  file=log)
    out[~ok] = np.nan
    return out


# ---------------------------------------------------------------- DeepLog

def deeplog_scores(g: dict, ok: np.ndarray, log=sys.stderr) -> np.ndarray:
    """DeepLog parameter-value model on the minute vector.  For day D the
    LSTM trains on the fit window (the last FIT_DAYS recorded days of the
    segment): DL_EPOCHS_FIRST epochs for a new model, then DL_EPOCHS_DAY
    each day from the weights of the day before.  Each column's squared
    error is a Gaussian tail against the out-of-sample errors of the
    previous HIST_DAYS recorded days; Benjamini-Hochberg across columns."""
    import torch
    from scipy.special import log_ndtr
    torch.manual_seed(0)
    torch.use_deterministic_algorithms(True)
    x, minute = g["x"], g["minute"]
    n, C = x.shape
    valid = ~g["masked"]
    seg = g["seg_start"]
    first = np.where(valid)[0][:3 * 1440]
    mu, sd = x[first].mean(0), x[first].std(0) + 1e-6
    z = np.clip((x - mu) / sd, -DL_CLIP, DL_CLIP).astype(np.float32)
    # a sample at t needs DL_HIST valid minutes before it and t itself ok
    win_ok = np.zeros(n, dtype=bool)
    run = 0
    for i in range(n):
        win_ok[i] = ok[i] and run >= DL_HIST
        run = run + 1 if valid[i] else 0
    zt = torch.from_numpy(z)

    class Net(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.lstm = torch.nn.LSTM(C, DL_HIDDEN, DL_LAYERS, batch_first=True)
            self.out = torch.nn.Linear(DL_HIDDEN, C)

        def forward(self, xb):
            h, _ = self.lstm(xb)
            return self.out(h[:, -1])

    def batches(idx):
        for k in range(0, len(idx), DL_BATCH):
            b = torch.from_numpy(idx[k:k + DL_BATCH])
            off = torch.arange(-DL_HIST, 0)
            yield zt[b[:, None] + off[None, :]], zt[b]

    def predict(net, idx):
        net.eval()
        out = []
        with torch.no_grad():
            for xb, _ in batches(idx):
                out.append(net(xb).numpy())
        return np.vstack(out) if out else np.zeros((0, C), np.float32)

    out = np.full(n, np.nan)
    rec: deque = deque(maxlen=FIT_DAYS)
    err_hist: deque = deque(maxlen=HIST_DAYS)
    net, opt, cur_seg = None, None, None
    rng = np.random.default_rng(0)
    t0 = time.time()
    for d in range(g["n_days"]):
        a, b = d * 1440, (d + 1) * 1440
        s0 = seg[a]
        if s0 != cur_seg:
            net, opt, cur_seg = None, None, s0
            rec.clear(); err_hist.clear()
        if len(rec) >= MIN_FIT_DAYS:
            fit_idx = np.concatenate([np.where(win_ok[r:r + 1440])[0] + r
                                      for r in rec])
            new = net is None
            if new:
                net = Net()
                opt = torch.optim.Adam(net.parameters(), lr=DL_LR)
            net.train()
            for _ in range(DL_EPOCHS_FIRST if new else DL_EPOCHS_DAY):
                for xb, yb in batches(rng.permutation(fit_idx)):
                    opt.zero_grad()
                    loss = torch.nn.functional.mse_loss(net(xb), yb)
                    loss.backward()
                    opt.step()
            day_idx = np.where(win_ok[a:b])[0] + a
            if len(day_idx):
                err = (predict(net, day_idx) - z[day_idx]) ** 2
                if len(err_hist) >= HIST_DAYS:
                    h = np.vstack(err_hist)
                    m_, s_ = h.mean(0), np.maximum(h.std(0), 1e-6)
                    out[day_idx] = bh_log_min(log_ndtr(-(err - m_) / s_))
                err_hist.append(err)
        if valid[a:b].sum() >= REC_MIN:
            rec.append(a)
        if (d + 1) % 50 == 0:
            print(f"[arrival_eval] deeplog day {d + 1}/{g['n_days']} "
                  f"{time.time() - t0:.0f}s", file=log)
    out[~ok] = np.nan
    return out


# ---------------------------------------------------------------- Markov chain

def _markov_day_sql(day: _dt.date, t0: int) -> str:
    """(minute index in the day, previous token, token, count) for the
    consecutive packets of each source on one UTC day."""
    tok = ("((coalesce(proto, 0)::BIGINT * 256 + coalesce(tcp_flags, 0)::BIGINT)"
           " * 65537 + coalesce(dst_port::BIGINT + 1, 0))")
    return f"""
        WITH p AS (
            SELECT ts, src_ip, {tok} AS tok FROM packets
            WHERE dt = DATE '{day}' AND {ars.NOT_NTP}
        ), q AS (
            SELECT ts, tok, lag(tok) OVER (PARTITION BY src_ip
                                           ORDER BY ts, tok) AS prev
            FROM p
        )
        SELECT ((epoch(date_trunc('minute', ts))::BIGINT - {t0}) // 60)::BIGINT AS mi,
               prev, tok, count(*)::BIGINT AS n
        FROM q WHERE prev IS NOT NULL GROUP BY ALL
    """


def markov_surprise(day: "pd.DataFrame", fit: "pd.DataFrame") -> "pd.Series":
    """Mean -log2 P(tok | prev) of each minute, weighted by count.
    P(b|a) = (c(a,b) + B * P(b)) / (c(a) + B), P(b) = (c(b) + 1) / (N + V + 1)
    from the fit-window pair counts ``fit`` (prev, tok, n)."""
    import pandas as pd
    c_ab = fit.groupby(["prev", "tok"], sort=False)["n"].sum().rename("c_ab")
    c_a = fit.groupby("prev", sort=False)["n"].sum().rename("c_a")
    c_b = fit.groupby("tok", sort=False)["n"].sum().rename("c_b")
    n_tot, v = float(c_b.sum()), float(len(c_b))
    d = day.join(c_ab, on=["prev", "tok"]).join(c_a, on="prev").join(c_b, on="tok")
    d = d.fillna({"c_ab": 0.0, "c_a": 0.0, "c_b": 0.0})
    p_b = (d["c_b"] + 1.0) / (n_tot + v + 1.0)
    p = (d["c_ab"] + MK_BACKOFF * p_b) / (d["c_a"] + MK_BACKOFF)
    d["bits"] = -np.log2(p) * d["n"]
    agg = d.groupby("mi", sort=True)[["bits", "n"]].sum()
    return agg["bits"] / agg["n"]


def markov_scores(g: dict, start: _dt.date, ok: np.ndarray,
                  log=sys.stderr) -> np.ndarray:
    """Global Markov-chain surprise per minute.  The transition table for
    day D comes from the last FIT_DAYS recorded days of the segment (masked
    minutes left out); a day with fewer than MIN_FIT_DAYS gets no score."""
    import pandas as pd
    n = len(g["minute"])
    out = np.full(n, np.nan)
    valid = ~g["masked"]
    seg = g["seg_start"]
    rec: deque = deque(maxlen=FIT_DAYS)
    cur_seg = None
    con = lib.duck()
    lib.register_views(con)
    t0 = time.time()
    for d in range(g["n_days"]):
        a = d * 1440
        day = start + _dt.timedelta(days=d)
        if seg[a] != cur_seg:
            rec.clear(); cur_seg = seg[a]
        df = con.execute(_markov_day_sql(day, int(g["minute"][a]))).df()
        df = df[(df["mi"] >= 0) & (df["mi"] < 1440)]
        df = df[valid[a + df["mi"].to_numpy()]]
        if len(rec) >= MIN_FIT_DAYS and len(df):
            fit = pd.concat(list(rec), ignore_index=True)
            s = markov_surprise(df, fit)
            out[a + s.index.to_numpy()] = s.to_numpy()
        if valid[a:a + 1440].sum() >= REC_MIN and len(df):
            rec.append(df[["prev", "tok", "n"]])
        if (d + 1) % 50 == 0:
            print(f"[arrival_eval] markov day {d + 1}/{g['n_days']} "
                  f"{time.time() - t0:.0f}s", file=log)
    con.close()
    out[~ok] = np.nan
    return out


# ---------------------------------------------------------------- SOM

def _som_grid() -> np.ndarray:
    i, j = np.meshgrid(np.arange(SOM_SIDE), np.arange(SOM_SIDE), indexing="ij")
    return np.stack([i.ravel(), j.ravel()], axis=1).astype(float)


def _som_bmu(w: np.ndarray, z: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Best-matching cell and its Euclidean distance for each row of z."""
    d2 = (z * z).sum(1)[:, None] - 2 * z @ w.T + (w * w).sum(1)[None, :]
    bmu = d2.argmin(1)
    return bmu, np.sqrt(np.maximum(d2[np.arange(len(z)), bmu], 0.0))


def som_train(w: np.ndarray, z: np.ndarray, steps: int, s0: float,
              s1: float) -> np.ndarray:
    """Batch SOM: each step moves every cell to the neighbourhood-weighted
    mean of the rows whose best cell is near it (Gaussian, sigma s0 -> s1)."""
    grid = _som_grid()
    gd2 = ((grid[:, None, :] - grid[None, :, :]) ** 2).sum(-1)
    k = len(w)
    for it in range(steps):
        sig = s0 * (s1 / s0) ** (it / max(steps - 1, 1))
        h = np.exp(-gd2 / (2 * sig * sig))
        bmu, _ = _som_bmu(w, z)
        sums = np.zeros_like(w)
        np.add.at(sums, bmu, z)
        cnt = np.bincount(bmu, minlength=k).astype(float)
        num, den = h @ sums, h @ cnt
        upd = den > 1e-12
        w = w.copy()
        w[upd] = num[upd] / den[upd, None]
    return w


def som_scores(g: dict, ok: np.ndarray, log=sys.stderr) -> np.ndarray:
    """Quantization error of each minute against the map of its day, as a
    ratio to the median error of the fit window.  Day D trains on the last
    FIT_DAYS recorded days of the segment: a new map (random fit rows, seed
    0) gets SOM_NEW steps, later days warm-start with SOM_DAY steps."""
    x = g["x"]
    n = len(x)
    valid = ~g["masked"]
    seg = g["seg_start"]
    first = np.where(valid)[0][:3 * 1440]
    mu, sd = x[first].mean(0), x[first].std(0) + 1e-6
    z = np.clip((x - mu) / sd, -DL_CLIP, DL_CLIP)
    out = np.full(n, np.nan)
    rec: deque = deque(maxlen=FIT_DAYS)
    w, cur_seg = None, None
    rng = np.random.default_rng(0)
    t0 = time.time()
    for d in range(g["n_days"]):
        a, b = d * 1440, (d + 1) * 1440
        if seg[a] != cur_seg:
            w, cur_seg = None, seg[a]
            rec.clear()
        if len(rec) >= MIN_FIT_DAYS:
            fit = np.concatenate([np.where(valid[r:r + 1440])[0] + r for r in rec])
            zf = z[fit]
            if w is None:
                w = zf[rng.choice(len(zf), SOM_SIDE * SOM_SIDE, replace=False)]
                w = som_train(w, zf, *SOM_NEW)
            else:
                w = som_train(w, zf, *SOM_DAY)
            _, qe_fit = _som_bmu(w, zf)
            med = max(float(np.median(qe_fit)), 1e-9)
            day = np.where(ok[a:b])[0] + a
            if len(day):
                out[day] = _som_bmu(w, z[day])[1] / med
        if valid[a:b].sum() >= REC_MIN:
            rec.append(a)
        if (d + 1) % 50 == 0:
            print(f"[arrival_eval] som day {d + 1}/{g['n_days']} "
                  f"{time.time() - t0:.0f}s", file=log)
    out[~ok] = np.nan
    return out


# ---------------------------------------------------------------- RRCF

def _rrcf_kernels():
    from numba import njit

    @njit(cache=True)
    def build(z, ids, seed, left, right, cdim, cval, size, lo, hi):
        """One random cut tree on z[ids]; cut dimension in proportion to
        its range, cut value uniform.  Returns the number of nodes."""
        np.random.seed(seed)
        m = len(ids)
        st_n = np.empty(2 * m, np.int64); st_a = np.empty(2 * m, np.int64)
        st_b = np.empty(2 * m, np.int64)
        top = 0; nn = 1
        st_n[0] = 0; st_a[0] = 0; st_b[0] = m
        while top >= 0:
            nd, a, b = st_n[top], st_a[top], st_b[top]
            top -= 1
            for jj in range(z.shape[1]):       # bounding box of the subtree
                mn = z[ids[a], jj]; mx = mn
                for ii in range(a + 1, b):
                    vv = z[ids[ii], jj]
                    if vv < mn:
                        mn = vv
                    if vv > mx:
                        mx = vv
                lo[nd, jj] = mn; hi[nd, jj] = mx
            size[nd] = b - a
            r = hi[nd] - lo[nd]
            tot = r.sum()
            if b - a == 1 or tot <= 0.0:
                left[nd] = -1; right[nd] = -1
                continue
            u = np.random.random() * tot
            d = 0
            acc = r[0]
            while acc < u and d < len(r) - 1:
                d += 1
                acc += r[d]
            c = lo[nd, d] + np.random.random() * r[d]
            if c >= hi[nd, d]:
                c = lo[nd, d]
            i, j = a, b - 1
            while i <= j:                      # partition ids[a:b] on the cut
                if z[ids[i], d] <= c:
                    i += 1
                else:
                    tmp = ids[i]; ids[i] = ids[j]; ids[j] = tmp
                    j -= 1
            if i == a or i == b:               # degenerate: make a leaf
                left[nd] = -1; right[nd] = -1
                continue
            cdim[nd] = d; cval[nd] = c
            left[nd] = nn; right[nd] = nn + 1
            top += 1; st_n[top] = nn; st_a[top] = a; st_b[top] = i
            top += 1; st_n[top] = nn + 1; st_a[top] = i; st_b[top] = b
            nn += 2
        return nn

    @njit(cache=True)
    def codisp(q, seed, left, right, cdim, cval, size, lo, hi):
        """CoDisp of each row of q inserted (not kept) into the tree."""
        np.random.seed(seed)
        out = np.zeros(len(q))
        path = np.empty(4096, np.int64)
        for k in range(len(q)):
            p = q[k]
            nd = 0; depth = 0
            while True:
                path[depth] = nd
                elo = np.minimum(lo[nd], p); ehi = np.maximum(hi[nd], p)
                r = ehi - elo
                tot = r.sum()
                sep = False
                if tot > 0.0:
                    u = np.random.random() * tot
                    d = 0
                    acc = r[0]
                    while acc < u and d < len(r) - 1:
                        d += 1
                        acc += r[d]
                    c = elo[d] + np.random.random() * r[d]
                    sep = ((p[d] <= c and c < lo[nd, d]) or
                           (hi[nd, d] <= c and c < p[d]))
                if sep or left[nd] < 0:
                    best = float(size[nd])     # p's sibling is this subtree
                    for lv in range(depth - 1, -1, -1):
                        par = path[lv]; ch = path[lv + 1]
                        sib = right[par] if left[par] == ch else left[par]
                        best = max(best, size[sib] / (size[ch] + 1.0))
                    out[k] = best
                    break
                nd = left[nd] if p[cdim[nd]] <= cval[nd] else right[nd]
                depth += 1
        return out
    return build, codisp


def rrcf_scores(g: dict, ok: np.ndarray, log=sys.stderr) -> np.ndarray:
    """Mean CoDisp over RRCF_TREES trees, each built on RRCF_SAMPLE random
    unmasked minutes of the fit window of the day (seeded by day)."""
    build, codisp = _rrcf_kernels()
    x = g["x"]
    n, C = x.shape
    valid = ~g["masked"]
    seg = g["seg_start"]
    first = np.where(valid)[0][:3 * 1440]
    mu, sd = x[first].mean(0), x[first].std(0) + 1e-6
    z = np.clip((x - mu) / sd, -DL_CLIP, DL_CLIP)
    out = np.full(n, np.nan)
    rec: deque = deque(maxlen=FIT_DAYS)
    cur_seg = None
    m = 2 * RRCF_SAMPLE
    left = np.empty(m, np.int64); right = np.empty(m, np.int64)
    cdim = np.zeros(m, np.int64); cval = np.zeros(m)
    size = np.zeros(m, np.int64); lo = np.zeros((m, C)); hi = np.zeros((m, C))
    t0 = time.time()
    for d in range(g["n_days"]):
        a, b = d * 1440, (d + 1) * 1440
        if seg[a] != cur_seg:
            cur_seg = seg[a]; rec.clear()
        day = np.where(ok[a:b])[0] + a
        if len(rec) >= MIN_FIT_DAYS and len(day):
            fit = np.concatenate([np.where(valid[r:r + 1440])[0] + r for r in rec])
            rng = np.random.default_rng(d)
            acc = np.zeros(len(day))
            q = np.ascontiguousarray(z[day])
            for tr in range(RRCF_TREES):
                ids = rng.choice(fit, min(RRCF_SAMPLE, len(fit)), replace=False)
                build(z, ids.astype(np.int64), int(d * 1000 + tr), left, right,
                      cdim, cval, size, lo, hi)
                acc += codisp(q, int(d * 1000 + tr + 500), left, right, cdim,
                              cval, size, lo, hi)
            out[day] = acc / RRCF_TREES
        if valid[a:b].sum() >= REC_MIN:
            rec.append(a)
        if (d + 1) % 50 == 0:
            print(f"[arrival_eval] rrcf day {d + 1}/{g['n_days']} "
                  f"{time.time() - t0:.0f}s", file=log)
    out[~ok] = np.nan
    return out


# ---------------------------------------------------------------- sketches

def _cms_kernel():
    from numba import njit

    @njit(cache=True)
    def day(rec_min, key, c, n_min, valid, reset_fast, reset_all, fast,
            slow, ha, hb, ticks, df, ds, tau_f, tau_s, out):
        """One day of the decayed Count-Min pair.  Each tick decays both
        copies (factors df, ds), adds the minute's port counts, then scores
        each port of the minute with the final counts."""
        rows, cols = fast.shape
        p = 0
        nrec = len(rec_min)
        for j in range(n_min):
            if reset_all[j]:
                fast[:] = 0.0; slow[:] = 0.0; ticks[0] = 0.0
            elif reset_fast[j]:
                fast[:] = 0.0
            q = p
            while q < nrec and rec_min[q] == j:
                q += 1
            if not valid[j]:
                p = q
                continue
            ticks[0] += 1.0
            fast *= df
            slow *= ds
            for i in range(p, q):
                for r in range(rows):
                    h = ((ha[r] * (key[i] % 2147483647) + hb[r]) % 2147483647) % cols
                    fast[r, h] += c[i]
                    slow[r, h] += c[i]
            best = 0.0
            for i in range(p, q):
                ef = 1e300; es = 1e300
                for r in range(rows):
                    h = ((ha[r] * (key[i] % 2147483647) + hb[r]) % 2147483647) % cols
                    ef = min(ef, fast[r, h]); es = min(es, slow[r, h])
                v = np.log2((ef / tau_f + 1.0) / (es / tau_s + 1.0))
                best = max(best, v)
            out[j] = best if ticks[0] >= tau_s else np.nan
            p = q
    return day


def sketch_scores(g: dict, start: _dt.date, ok: np.ndarray,
                  log=sys.stderr) -> tuple[np.ndarray, np.ndarray, dict]:
    """``cms`` and ``hll`` minute scores (see the module docstring), plus
    the HyperLogLog relative error against the exact distinct count."""
    kern = _cms_kernel()
    n = len(g["minute"])
    cms = np.full(n, np.nan)
    hll = np.full(n, np.nan)
    valid = ~g["masked"]
    seg = g["seg_start"]
    reset_fast = g["since"] == 0
    reset_all = np.zeros(n, dtype=bool)
    reset_all[1:] = seg[1:] != seg[:-1]
    fast = np.zeros((CMS_ROWS, CMS_COLS)); slow = np.zeros_like(fast)
    rng = np.random.default_rng(11)
    ha = rng.integers(1, _P, size=CMS_ROWS, dtype=np.int64)
    hb = rng.integers(0, _P, size=CMS_ROWS, dtype=np.int64)
    ticks = np.zeros(1)
    df, ds = math.exp(-1.0 / CMS_TAU[0]), math.exp(-1.0 / CMS_TAU[1])
    rec: deque = deque(maxlen=FIT_DAYS)
    cur_seg, pending = None, np.nan
    err_sum, err_abs, err_n = 0.0, 0.0, 0
    con = lib.duck()
    lib.register_views(con)
    t0 = time.time()
    for d in range(g["n_days"]):
        a = d * 1440
        day = start + _dt.timedelta(days=d)
        m0 = int(g["minute"][a])
        r = con.execute(f"""
            SELECT ((epoch(date_trunc('minute', ts))::BIGINT - {m0}) // 60)::BIGINT,
                   coalesce(dst_port::BIGINT, 65536 + coalesce(proto, 0)::BIGINT),
                   count(*)::DOUBLE
            FROM packets WHERE dt = DATE '{day}' AND {ars.NOT_NTP}
            GROUP BY ALL ORDER BY 1
        """).fetchnumpy()
        cols = list(r.values())
        out = np.full(1440, np.nan)
        kern(np.asarray(cols[0], np.int64), np.asarray(cols[1], np.int64),
             np.asarray(cols[2], np.float64), 1440, valid[a:a + 1440],
             reset_fast[a:a + 1440], reset_all[a:a + 1440], fast, slow, ha, hb,
             ticks, df, ds, CMS_TAU[0], CMS_TAU[1], out)
        cms[a:a + 1440] = out
        # HyperLogLog fan-out: distinct ports of each source per block
        fo = con.execute(f"""
            WITH s AS (
                SELECT ((epoch(date_trunc('minute', ts))::BIGINT - {m0}) // 60
                        // {HLL_BLOCK})::BIGINT AS blk, src_ip,
                       approx_count_distinct(dst_port) AS est,
                       count(DISTINCT dst_port) AS exact
                FROM packets WHERE dt = DATE '{day}' AND {ars.NOT_NTP}
                GROUP BY ALL
            )
            SELECT blk, max(est)::DOUBLE, sum(est - exact)::DOUBLE,
                   sum(abs(est - exact))::DOUBLE, sum(exact)::DOUBLE
            FROM s GROUP BY blk ORDER BY blk
        """).fetchall()
        if seg[a] != cur_seg:
            cur_seg = seg[a]; rec.clear(); pending = np.nan
        blk_val = np.full(1440 // HLL_BLOCK, np.nan)
        for blk, mx, es, ea, ex in fo:
            if 0 <= blk < len(blk_val):
                blk_val[blk] = math.log1p(mx)
                err_sum += es; err_abs += ea; err_n += ex
        if len(rec) >= MIN_FIT_DAYS:
            ref = np.concatenate(list(rec))
            ref = ref[np.isfinite(ref)]
            med = np.median(ref)
            mad = max(np.median(np.abs(ref - med)) * 1.4826, 1e-6)
            z = (blk_val - med) / mad
            for blk in range(len(blk_val)):     # block b scores block b + 1
                hll[a + blk * HLL_BLOCK:a + (blk + 1) * HLL_BLOCK] = pending
                pending = z[blk]
        else:
            pending = np.nan
        vmask = valid[a:a + 1440].reshape(-1, HLL_BLOCK).all(1)
        if valid[a:a + 1440].sum() >= REC_MIN:
            rec.append(np.where(vmask, blk_val, np.nan))
        if (d + 1) % 50 == 0:
            print(f"[arrival_eval] sketches day {d + 1}/{g['n_days']} "
                  f"{time.time() - t0:.0f}s", file=log)
    con.close()
    cms[~ok] = np.nan
    hll[~ok] = np.nan
    err = {"hll_bias": err_sum / max(err_n, 1), "hll_abs_err": err_abs / max(err_n, 1)}
    return cms, hll, err


# ---------------------------------------------------------------- reporting

def _day_ts(d: _dt.date) -> float:
    return _dt.datetime.combine(d, _dt.time(), _dt.timezone.utc).timestamp()


def in_period(minute: np.ndarray, name: str) -> np.ndarray:
    a, b = PERIODS[name]
    return (minute >= _day_ts(a)) & (minute < _day_ts(b) + 86400)


def _full_tables(sc: dict, minute: np.ndarray, common: np.ndarray,
                 ev: dict, rows: list[dict]) -> list[str]:
    """Per-year FA/yr at theta*, and event hits at fixed alarm budgets."""
    years = sorted({_dt.datetime.fromtimestamp(t, _dt.timezone.utc).year
                    for t in minute[common][[0, -1]]})
    years = list(range(years[0], years[-1] + 1))
    yr = np.array([_dt.datetime.fromtimestamp(t, _dt.timezone.utc).year
                   for t in minute[::1440]]).repeat(1440)[:len(minute)]
    md = ["", "## FA/yr at theta* for each calendar year", "",
          "| detector | " + " | ".join(str(y) for y in years) + " |",
          "| --- |" + " ---: |" * len(years)]
    for k in DETECTORS:
        s = np.where(common, sc[k], np.nan)
        cells = []
        for y in years:
            gm = gate_metrics(s, minute, common & (yr == y), ev)
            cells.append(f"{gm['fa_per_year']:.1f}")
            rows.append({"mode": "full", "detector": k,
                         "metric": f"fa_per_year_{y}", "value": gm["fa_per_year"]})
        md.append(f"| {k} | " + " | ".join(cells) + " |")
    md += ["", "## Events found at a fixed alarm budget", "",
           "The threshold is the score quantile that gives the stated number "
           "of alarm minutes for each day. An event is found when one or more "
           "of its minutes is at or above the threshold. Other episodes are "
           "the alarm episodes that do not touch an event window or its 6 h "
           "guard.", "",
           "| detector | budget | E1 | E2 | E3 | other episodes |",
           "| --- | ---: | :---: | :---: | :---: | ---: |"]
    for k in DETECTORS:
        v = np.where(common, sc[k], np.nan)
        fin = np.isfinite(v)
        for rate in (1, 10):
            th = np.quantile(v[fin], 1 - rate / 1440) if fin.any() else np.inf
            hit = {}
            for e, (a, b) in ev.items():
                w = (minute + 60 > a) & (minute < b) & fin
                hit[e] = bool((v[w] >= th).any())
            eps = episodes(np.sort(minute[fin & (v >= th)]), EPISODE_JOIN_MIN * 60)
            other = sum(1 for p in eps if not any(
                p[1] > a - EVENT_GUARD_S and p[0] < b + EVENT_GUARD_S
                for a, b in ev.values()))
            md.append(f"| {k} | {rate}/day | " + " | ".join(
                "yes" if hit[e] else "no" for e in ev) + f" | {other} |")
            rows += [{"mode": "full", "detector": k, "metric":
                      f"hit_{e}_rate{rate}", "value": float(hit[e])} for e in ev]
            rows.append({"mode": "full", "detector": k,
                         "metric": f"other_episodes_rate{rate}", "value": other})
    return md


def rescore(args: argparse.Namespace) -> lib.Report:
    """Gate tables again from a saved arrival_scores_<mode>.parquet (no
    detector run).  The one-step error and HyperLogLog rows are copied from
    the saved arrival_eval_<mode>.parquet."""
    st = pq.read_table(OUT / f"arrival_scores_{args.mode}.parquet")
    minute = st["minute"].cast(pa.int64()).to_numpy() / 1e6
    sc = {k: st[k].to_numpy(zero_copy_only=False).astype(float) for k in DETECTORS}
    common = np.all(np.stack([np.isfinite(sc[k]) for k in GATE]), axis=0)
    # fill the minute grid so that episode and year arithmetic sees gaps
    t0 = minute[0] - (minute[0] % 86400)
    n = int((minute[-1] - t0) // 60) + 1
    idx = ((minute - t0) // 60).astype(np.int64)
    grid = t0 + 60.0 * np.arange(n)
    full = {k: np.full(n, np.nan) for k in DETECTORS}
    for k in DETECTORS:
        full[k][idx] = sc[k]
    com = np.zeros(n, dtype=bool)
    com[idx] = common
    old = pq.read_table(OUT / f"arrival_eval_{args.mode}.parquet").to_pylist()
    rows = [r for r in old if r["metric"].startswith(("mse_", "hll_"))]
    md = [f"- mode: `{args.mode}` (gate tables made again from "
          f"arrival_scores_{args.mode}.parquet)",
          f"- minutes with all gate scores: {int(com.sum()):,}", ""]
    md += ["## One-step error of the readouts", "",
           "| readout | ridge (per row) | mean squared error |",
           "| --- | ---: | ---: |"]
    md += [f"| {r['detector']} | {r['metric'][10:]} | {r['value']:.5f} |"
           for r in rows if r["metric"].startswith("mse_")]
    hl = {r["metric"]: r["value"] for r in rows if r["metric"].startswith("hll_")}
    if hl:
        md += ["", f"- HyperLogLog fan-out error against the exact count: bias "
               f"{hl['hll_bias']:+.4f}, mean absolute error {hl['hll_abs_err']:.4f}"]
    md += _gate_tables(args.mode, full, grid, com, rows)
    rep = lib.Report(name="arrival_eval", rows=rows, schema=RESULT_SCHEMA,
                     markdown="\n".join(md) + "\n")
    rep.write(suffix=args.mode)
    print(f"[arrival_eval] wrote {OUT}/arrival_eval_{args.mode}.md", file=sys.stderr)
    return rep


def _gate_tables(mode: str, sc: dict, minute: np.ndarray, common: np.ndarray,
                 rows: list[dict]) -> list[str]:
    ev = {k: (_dt.datetime.fromisoformat(a).timestamp(),
              _dt.datetime.fromisoformat(b).timestamp())
          for k, (a, b) in EVENTS.items()}
    if mode == "gate":
        test = (in_period(minute, "test1") | in_period(minute, "test2")) & common
    else:
        test = common.copy()
    md = ["", "## Gate (ARCHITECTURE §9.6)", "",
          "theta* uses the events that have a score. An event with no score "
          "shows `n/s`.", "",
          "| detector | theta* | E1 max | E2 max | E3 max | episodes | FA | FA/yr |",
          "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    fmt = lambda v: f"{v:.3f}" if np.isfinite(v) else "n/s"
    res_g = {}
    for k in DETECTORS:
        s = np.where(common, sc[k], np.nan)
        gm = gate_metrics(s, minute, test, ev)
        res_g[k] = gm
        for mk, mv in gm.items():
            rows.append({"mode": mode, "detector": k, "metric": mk,
                         "value": float(mv)})
        md.append(f"| {k} | {fmt(gm['theta'])} | {fmt(gm['max_E1'])} | "
                  f"{fmt(gm['max_E2'])} | {fmt(gm['max_E3'])} | "
                  f"{gm['episodes']} | {gm['fa']} | {gm['fa_per_year']:.1f} |")
    p = res_g["ngrc_htm"]["fa_per_year"]
    passed = all(p < res_g[k]["fa_per_year"] for k in GATE[1:])
    md += ["", f"**Gate: {'pass' if passed else 'failure'}** "
           f"(ngrc_htm FA/yr {p:.1f} against "
           + ", ".join(f"{k} {res_g[k]['fa_per_year']:.1f}" for k in GATE[1:])
           + ")"]
    rows.append({"mode": mode, "detector": "ngrc_htm", "metric": "pass",
                 "value": float(passed)})
    if mode == "full":
        md += _full_tables(sc, minute, common, ev, rows)
    return md


def run(args: argparse.Namespace) -> lib.Report:
    if args.from_scores:
        return rescore(args)
    if args.mode == "dev":
        start, end = _dt.date(2024, 7, 25), PERIODS["dev"][1]
    elif args.mode == "gate":
        start, end = _dt.date(2024, 2, 8), PERIODS["test2"][1]
    else:
        mm = pq.read_table(SERIES, columns=["minute"])["minute"]
        start, end = (v.as_py().date() for v in (mm[0], mm[-1]))
    g = load_grid(start, end)
    res = run_detectors(g, ridge_ngrc=args.ridge_ngrc, ridge_ar=args.ridge_ar)
    sc, minute = res["scores"], g["minute"]
    sc["midas_r"] = midas_scores(g, start, res["ok"])
    sc["hst"] = hst_scores(g, res["ok"])
    sc["deeplog"] = deeplog_scores(g, res["ok"])
    sc["markov"] = markov_scores(g, start, res["ok"])
    sc["som"] = som_scores(g, res["ok"])
    sc["rrcf"] = rrcf_scores(g, res["ok"])
    sc["cms"], sc["hll"], hll_err = sketch_scores(g, start, res["ok"])
    common = np.all(np.stack([np.isfinite(sc[k]) for k in GATE]), axis=0)
    rows: list[dict] = []
    md = [f"- mode: `{args.mode}`, days {start} to {end}, ridge ngrc "
          f"{args.ridge_ngrc:g}, ar {args.ridge_ar:g} (per fit row)",
          f"- minutes with all gate scores: {int(common.sum()):,}", ""]
    md += ["## One-step error of the readouts", "",
           "| readout | ridge (per row) | mean squared error |",
           "| --- | ---: | ---: |"]
    for (mname, lam), e in res["mse"].items():
        md.append(f"| {mname} | {lam:g} | {e:.5f} |")
        rows.append({"mode": args.mode, "detector": mname, "metric":
                     f"mse_ridge_{lam:g}", "value": e})
    md += ["", f"- HyperLogLog fan-out error against the exact count: bias "
           f"{hll_err['hll_bias']:+.4f}, mean absolute error "
           f"{hll_err['hll_abs_err']:.4f} (fraction of the exact distinct ports)"]
    rows += [{"mode": args.mode, "detector": "hll", "metric": k, "value": v}
             for k, v in hll_err.items()]
    if args.mode == "dev":
        dev = in_period(minute, "dev") & common
        md += ["", "## Alarm episodes in the development period", "",
               "Threshold at the score quantile that gives the stated "
               "alarm-minute rate.", "",
               "| detector | 1/day | 10/day |", "| --- | ---: | ---: |"]
        for k in DETECTORS:
            v = sc[k][dev]
            cells = []
            for rate in (1, 10):
                q = 1 - rate / 1440
                th = np.quantile(v[np.isfinite(v)], q) if np.isfinite(v).any() else np.inf
                ep = episodes(np.sort(minute[dev][v >= th]), EPISODE_JOIN_MIN * 60)
                cells.append(len(ep))
                rows.append({"mode": "dev", "detector": k,
                             "metric": f"episodes_rate{rate}", "value": len(ep)})
            md.append(f"| {k} | {cells[0]} | {cells[1]} |")
    else:
        md += _gate_tables(args.mode, sc, minute, common, rows)
    OUT.mkdir(parents=True, exist_ok=True)
    keep = np.isfinite(sc["ngrc_htm"]) | common
    st = pa.table({"minute": pa.array((minute[keep] * 1e6).astype(np.int64),
                                      type=pa.timestamp("us", tz="UTC")),
                   **{k: pa.array(sc[k][keep].astype(np.float32)) for k in DETECTORS}})
    tmp = OUT / f"arrival_scores_{args.mode}.parquet.tmp"
    pq.write_table(st, tmp, compression="zstd")
    tmp.replace(OUT / f"arrival_scores_{args.mode}.parquet")
    rep = lib.Report(name="arrival_eval", rows=rows, schema=RESULT_SCHEMA,
                     markdown="\n".join(md) + "\n")
    rep.write(suffix=args.mode)
    print(f"[arrival_eval] wrote {OUT}/arrival_eval_{args.mode}.md", file=sys.stderr)
    return rep


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("dev", "gate", "full"), required=True)
    # dev one-step error (arrival_eval_dev.md, 2026-10-24): ngrc 1, ar 0.1
    ap.add_argument("--from-scores", action="store_true",
                    help="make the gate tables again from the saved "
                         "arrival_scores_<mode>.parquet (no detector run)")
    ap.add_argument("--ridge-ngrc", type=float, default=1.0)
    ap.add_argument("--ridge-ar", type=float, default=1e-1)
    run(ap.parse_args())
    return 0


if __name__ == "__main__":
    sys.exit(main())

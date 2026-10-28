"""Unit tests for bench/arrival_eval pure helpers (Phase 2 gate math).

The arrays below are small hand-made numbers that pin the arithmetic of
Benjamini-Hochberg, episode joining, theta* / FA-per-year and the ridge;
they are not honeypot data and no detector result depends on them.
Detection is measured only on the real corpus by ``arrival_eval --mode``.
"""
from __future__ import annotations

import math

import numpy as np
import pytest

from bench import arrival_eval as ae


def test_bh_log_min_matches_hand_computation():
    p = np.array([[0.01, 0.04, 0.03, 0.5]])
    # sorted 0.01, 0.03, 0.04, 0.5 -> x4/1, x4/2, x4/3, x4/4 -> min 0.04
    got = ae.bh_log_min(np.log(p))
    assert got[0] == pytest.approx(-math.log10(0.04))
    assert ae.bh_log_min(np.log(np.ones((1, 3))))[0] == pytest.approx(0.0)


def test_episodes_join_within_gap():
    ts = np.array([0, 60, 120, 60 * 40, 60 * 41, 60 * 200], dtype=float)
    eps = ae.episodes(ts, 30 * 60)
    assert eps == [(0, 60 * 3), (60 * 40, 60 * 42), (60 * 200, 60 * 201)]


def test_gate_metrics_theta_and_false_alarms():
    ts = 60.0 * np.arange(2000)
    score = np.zeros(2000)
    score[100] = 5.0          # event A
    score[1500] = 3.0         # event B -> theta* = 3
    score[800] = 4.0          # far from both events: one false alarm
    score[110] = 9.0          # inside the guard of event A: not counted
    ev = {"A": (ts[100], ts[101]), "B": (ts[1500], ts[1501])}
    test = np.ones(2000, dtype=bool)
    gm = ae.gate_metrics(score, ts, test, ev)
    assert gm["theta"] == 3.0
    assert gm["fa"] == 1
    assert gm["fa_per_year"] == pytest.approx(1 / (2000 / 525_600))


def test_rolling_mean_resets_on_gap():
    x = np.arange(8, dtype=float)[:, None]
    ok = np.array([1, 1, 1, 0, 1, 1, 1, 1], dtype=bool)
    m = ae.rolling_mean(x, ok, 3)
    assert np.isnan(m[:2, 0]).all() and m[2, 0] == pytest.approx(1.0)
    assert np.isnan(m[3:6, 0]).all() and m[6, 0] == pytest.approx(5.0)


def test_ridge_does_not_shrink_bias():
    rng = np.random.default_rng(0)
    f = np.hstack([np.ones((500, 1)), rng.normal(size=(500, 2))])
    y = 7.0 + 0.0 * f[:, 1:2]
    w = ae._ridge(f.T @ f, f.T @ y, 10.0, 500)
    assert w[0, 0] == pytest.approx(7.0, abs=1e-6)


def test_midas_kernel_flags_burst_and_resets():
    kern = ae._midas_kernel()
    ha, hb = ae._midas_hashes()
    n_min = 30
    # edge (1, 80) once per minute; at minute 20 one burst of 50 on (2, 22)
    rec_min = list(range(n_min)) + [20]
    u = [1] * n_min + [2]
    v = [80] * n_min + [22]
    c = [1.0] * n_min + [50.0]
    order = np.argsort(rec_min, kind="stable")
    arr = [np.asarray(a)[order] for a in (rec_min, u, v, c)]
    cur = np.zeros((3, ae.MIDAS_ROWS, ae.MIDAS_COLS)); tot = np.zeros_like(cur)
    out = np.zeros(n_min); t_tick = np.zeros(1)
    z = np.zeros(n_min, dtype=bool)
    kern(arr[0].astype(np.int64), arr[1].astype(np.int64), arr[2].astype(np.int64),
         arr[3].astype(np.float64), n_min, ~z, z, z, cur, tot, ha, hb, t_tick, out)
    assert out[20] == out.max() and out[20] > 10 * np.median(out[5:20])
    assert t_tick[0] == n_min
    reset = z.copy(); reset[0] = True
    cur[:] = 1.0; tot[:] = 1.0; t_tick[0] = 99.0
    kern(arr[0][:1].astype(np.int64), arr[1][:1].astype(np.int64),
         arr[2][:1].astype(np.int64), arr[3][:1].astype(np.float64), 1,
         ~z[:1], z[:1], reset[:1], cur, tot, ha, hb, t_tick, out[:1])
    assert t_tick[0] == 1.0 and tot.sum() == 3 * ae.MIDAS_ROWS


def test_bocpd_sees_mean_shift_and_not_flat():
    b = ae.Bocpd()
    flat = [b.update(0.0 + 0.01 * ((i * 7) % 5 - 2)) for i in range(200)]
    assert max(flat[20:]) < 0.5
    shifted = [b.update(1.0 + 0.01 * ((i * 7) % 5 - 2)) for i in range(10)]
    assert max(shifted) > 0.5
    b.reset()
    assert len(b.r) == 1 and b.r[0] == 1.0


def test_markov_surprise_seen_vs_unseen_transition():
    import pandas as pd
    fit = pd.DataFrame({"prev": [1, 1, 2], "tok": [2, 2, 1], "n": [9, 0, 1]})
    day = pd.DataFrame({"mi": [0, 1], "prev": [1, 1], "tok": [2, 3], "n": [1, 1]})
    s = ae.markov_surprise(day, fit)
    # c(1,2) = 9, c(1) = 9, c(2) = 9, N = 10, V = 2 -> P(2) = 10 / 13
    p_seen = (9 + 10 / 13) / (9 + 1)
    p_new = (0 + 1 / 13) / (9 + 1)        # token 3 never seen: P(3) = 1 / 13
    assert s.loc[0] == pytest.approx(-math.log2(p_seen))
    assert s.loc[1] == pytest.approx(-math.log2(p_new))
    assert s.loc[1] > s.loc[0]


def test_som_fits_two_clusters_and_flags_far_point():
    rng = np.random.default_rng(1)
    z = np.vstack([rng.normal(0, 0.1, (200, 3)), rng.normal(3, 0.1, (200, 3))])
    w = z[rng.choice(len(z), ae.SOM_SIDE ** 2, replace=False)]
    w = ae.som_train(w, z, *ae.SOM_NEW)
    _, qe = ae._som_bmu(w, z)
    _, far = ae._som_bmu(w, np.array([[10.0, -10.0, 10.0]]))
    assert np.median(qe) < 0.3 and far[0] > 10 * np.median(qe)


def test_rrcf_codisp_flags_far_point():
    build, codisp = ae._rrcf_kernels()
    rng = np.random.default_rng(2)
    z = rng.normal(0, 1, (256, 3))
    m = 512
    left = np.empty(m, np.int64); right = np.empty(m, np.int64)
    cdim = np.zeros(m, np.int64); cval = np.zeros(m)
    size = np.zeros(m, np.int64); lo = np.zeros((m, 3)); hi = np.zeros((m, 3))
    q = np.array([[0.0, 0.0, 0.0], [12.0, -12.0, 12.0]])
    acc = np.zeros(2)
    for tr in range(20):
        nn = build(z, np.arange(256, dtype=np.int64), tr, left, right, cdim,
                   cval, size, lo, hi)
        assert size[0] == 256 and nn <= 2 * 256
        leaves = left[:nn] < 0
        assert size[:nn][leaves].sum() == 256
        acc += codisp(q, 100 + tr, left, right, cdim, cval, size, lo, hi)
    assert acc[1] > 5 * acc[0]


def test_cms_kernel_rate_ratio_flags_port_burst():
    kern = ae._cms_kernel()
    n_min = 3000                          # > tau_s so the score switches on
    rec_min = list(range(n_min)) + [2500]
    key = [80] * n_min + [4444]
    c = [5.0] * n_min + [200.0]
    order = np.argsort(rec_min, kind="stable")
    rm, k, cc = (np.asarray(v)[order] for v in (rec_min, key, c))
    fast = np.zeros((ae.CMS_ROWS, ae.CMS_COLS)); slow = np.zeros_like(fast)
    ha = np.array([3, 5, 7, 11], np.int64); hb = np.array([1, 2, 3, 4], np.int64)
    out = np.full(n_min, np.nan); ticks = np.zeros(1)
    z = np.zeros(n_min, dtype=bool)
    tf, ts = ae.CMS_TAU
    kern(rm.astype(np.int64), k.astype(np.int64), cc.astype(np.float64), n_min,
         ~z, z, z, fast, slow, ha, hb, ticks, math.exp(-1 / tf),
         math.exp(-1 / ts), tf, ts, out)
    assert np.isnan(out[: int(ts) - 1]).all()
    assert out[2500] == np.nanmax(out) and out[2500] > 4.0   # >16x the daily rate
    assert abs(out[2400]) < 0.5                               # steady port: ~0 bits

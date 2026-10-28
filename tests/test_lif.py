"""Unit tests for sg.lif, sg.stdp and the Phase 3 calibration (pure math).

The spike trains and retinas below are small hand-made numbers that pin
the arithmetic of the LIF bank, the Hawkes fit, the calibration and the
STDP network; they are not honeypot data and no detector result depends
on them.  Detection is measured only on the real corpus by
``bench/lif_eval.py`` and ``bench/stdp_eval.py``.
"""
from __future__ import annotations

import numpy as np
import pytest

from sg import lif, stdp


def _one(t, seg=None):
    t = np.asarray(t, dtype=float)
    seg = np.zeros(len(t), dtype=np.int64) if seg is None else np.asarray(seg)
    return t, seg, np.array([0, len(t)])


def test_lif_membrane_matches_closed_form():
    # regular spikes every 10 s, tau 10 s: the pre-spike potential tends to
    # e^-1 / (1 - e^-1); a metronome has (near) zero spread -> high regularity
    t, seg, st = _one(10.0 * np.arange(200))
    med = lif.median_iat(t, seg, st)
    assert med[0] == pytest.approx(10.0)
    _, reg = lif.bank_scores(t, seg, st, med, taus=np.array([10.0]),
                             band=(0.5, 2.0), change_band=(0.5, 2.0))
    assert reg[0] > 10.0       # log(mean / std) with std ~ 0


def test_lif_change_sees_a_rate_shift_not_a_steady_rate():
    steady = 10.0 * np.arange(400)
    shifted = np.r_[10.0 * np.arange(200), 1990.0 + 1.0 * np.arange(1, 201)]
    out = []
    for tr in (steady, shifted):
        t, seg, st = _one(tr)
        ch, _ = lif.bank_scores(t, seg, st, lif.median_iat(t, seg, st))
        out.append(ch[0])
    assert out[1] > 5 * max(out[0], 0.1)


def test_lif_resets_at_a_segment_change():
    # the same train in two segments scores like one segment: the 1-day
    # gap between them is not seen as a rate change
    a = 10.0 * np.arange(100)
    t, seg, st = _one(np.r_[a, a + 86400.0], np.r_[np.zeros(100), np.ones(100)])
    ch, _ = lif.bank_scores(t, seg, st, lif.median_iat(t, seg, st))
    t1, s1, st1 = _one(a)
    ch1, _ = lif.bank_scores(t1, s1, st1, lif.median_iat(t1, s1, st1))
    assert ch[0] == pytest.approx(ch1[0], abs=1e-9)


def test_hawkes_ks_is_small_for_poisson_and_large_for_a_metronome():
    rng = np.random.default_rng(1)
    pois = np.cumsum(rng.exponential(10.0, 2000))
    metro = 10.0 * np.arange(2000)
    ks = []
    for tr in (pois, metro):
        t, seg, st = _one(tr)
        k, br = lif.hawkes_scores(t, seg, st, lif.median_iat(t, seg, st))
        ks.append(k[0])
        assert 0.0 <= br[0] < 1.0
    assert ks[0] < 2.0 < ks[1]


def test_calibrate_rates_and_tail():
    ref = np.arange(1000, dtype=float)
    logn = np.zeros(1000)
    got = lif.calibrate(np.array([-1.0, 500.0, 5000.0]), np.zeros(3), ref, logn,
                        n_bins=1)
    assert got[0] == pytest.approx(0.0)
    assert got[1] == pytest.approx(-np.log10(501 / 1001), abs=1e-6)
    assert got[2] > 3.0        # beyond every reference: exponential tail


def test_stdp_learns_the_fit_mixes():
    # two port mixes in the fit window; a third mix is novel after training
    owner = np.repeat(np.arange(200), 2)
    port = np.where(np.arange(400) % 2 == 0, 22, 23)
    port[200:] = np.where(np.arange(200) % 2 == 0, 80, 443)
    ip, b, v = stdp.retinas(owner, port, np.ones(400, dtype=np.int64), 200)
    w0 = stdp.init_prototypes(ip, b, v, k=4, seed=0)
    w = stdp.train(ip, b, v, w0, epochs=2, seed=0)
    nov_fit = stdp.novelty(ip, b, v, w)
    q = stdp.retinas(np.array([0, 0]), np.array([3389, 5900]),
                     np.array([1, 1]), 1)
    assert nov_fit.max() < 0.05
    assert stdp.novelty(*q, w)[0] > 0.5

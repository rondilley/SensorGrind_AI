"""Unit tests for bench/baselines pure helpers.

These pin the ranking and chance arithmetic on tiny in-memory arrays (not
honeypot data), so they're valid under the no-synthetic-data rule.  Every
new detector is judged against these numbers, so a silent change here moves
every Phase 1-3 exit gate.
"""
from __future__ import annotations

import datetime as dt
import math

import numpy as np

from bench import baselines as bl


def test_ranks_desc_highest_first():
    r = bl.ranks_desc(np.array([0.1, 5.0, 2.0]))
    assert r.tolist() == [3, 1, 2]


def test_ranks_desc_constant_detector_gets_no_tie_advantage():
    # A constant score must not rank index 0 first by tie order.
    firsts = {int(np.argmin(bl.ranks_desc(np.zeros(50), seed=s)))
              for s in range(20)}
    assert len(firsts) > 1


def test_hit_chance_edges():
    assert bl.hit_chance(100, 0, 10) == 0.0
    assert bl.hit_chance(100, 5, 0) == 0.0
    assert bl.hit_chance(10, 5, 6) == 1.0          # pigeonhole


def test_hit_chance_matches_hypergeometric():
    n, w, k = 1440, 11, 60
    miss = math.comb(n - w, k) / math.comb(n, k)
    assert math.isclose(bl.hit_chance(n, w, k), 1 - miss, rel_tol=1e-9)


def test_robust_z_uses_median_mad_and_stays_finite():
    ref = np.array([1.0, 2.0, 3.0, 4.0, 100.0])
    z = bl.robust_z(np.array([3.0]), ref)
    assert z[0] == 0.0
    flat = bl.robust_z(np.array([5.0]), np.full(10, 5.0))
    assert np.isfinite(flat).all()


def test_interval_mask_overlap_is_half_open():
    utc = dt.timezone.utc
    base = dt.datetime(2024, 5, 9, tzinfo=utc)
    minutes = base.timestamp() + 60.0 * np.arange(5)
    # Mask 00:01:30 -> 00:03:00: touches minutes 1 and 2, not minute 3.
    mask = [(base + dt.timedelta(seconds=90), base + dt.timedelta(minutes=3),
             "gap")]
    assert bl.interval_mask(minutes, mask).tolist() == [
        False, True, True, False, False]

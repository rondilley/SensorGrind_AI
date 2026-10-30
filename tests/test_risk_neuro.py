"""Unit tests for the neuromorphic term of risk/compute_risk_score.

The rows are hand-written feature values that pin the arithmetic of
neuro_score (flag, day correction, caps, labels); they are not honeypot data.
"""
from __future__ import annotations

import math

import pytest

from risk import compute_risk_score as rs


def test_no_neuro_columns_scores_zero():
    assert rs.neuro_score({}) == (0.0, "")


def test_hdc_term_uses_the_lif_flag_and_day_correction():
    pts, label = rs.neuro_score({"neuro_hdc_days": 10, "neuro_hdc_proto": 5.5,
                                 "neuro_hdc_drift": 4.2})
    assert pts == pytest.approx(2.0 * (5.5 - rs.NEURO_FLAG - math.log10(10)))
    assert label == "hdc-proto=5.5"
    assert rs.neuro_score({"neuro_hdc_days": 1, "neuro_hdc_proto": 3.9})[0] == 0.0


def test_hdc_term_is_capped_and_shares_the_neuro_cap():
    hdc_only = rs.neuro_score({"neuro_hdc_days": 1, "neuro_hdc_drift": 20.0})
    assert hdc_only == (rs.NEURO_HDC_CAP, "hdc-drift=20.0")
    both = rs.neuro_score({"neuro_days": 1, "neuro_change": 20.0,
                           "neuro_hdc_days": 1, "neuro_hdc_proto": 20.0})
    assert both[0] == rs.NEURO_CAP
    assert both[1] == "lif-rate-shift=20.0, hdc-proto=20.0"


# ---------------------------------------------------------------- C1

def test_surprisal_one_detector_is_its_day_corrected_p():
    bits, name = rs.neuro_bits({"neuro_days": 10, "neuro_change": 7.0})
    assert name == "lif-change"
    assert bits == pytest.approx(6.0 * math.log2(10))       # p = 10 * 1e-7


def test_surprisal_combines_with_l_times_the_harmonic_mean():
    r = {"neuro_days": 1, "neuro_change": 6.0, "neuro_reg": 2.0}
    p1, p2 = 1e-6, 1e-2
    hm = 2 / (1 / p1 + 1 / p2)
    bits, name = rs.neuro_bits(r)
    assert bits == pytest.approx(-math.log2(2 * hm))
    assert name == "lif-change"
    # never above Bonferroni over the detectors: L * min p
    assert bits <= -math.log2(2 * p1) + 1e-9


def test_surprisal_term_needs_more_bits_than_log2_population():
    r = {"neuro_days": 1, "neuro_change": 6.0}              # 19.9 bits
    assert rs.neuro_surprisal(r, 2 ** 20) == (0.0, "")
    pts, label = rs.neuro_surprisal(r, 2 ** 10)
    assert pts == pytest.approx(min(rs.NEURO_CAP,
                                    rs.BITS_POINTS * (6 * math.log2(10) - 10)))
    assert label.startswith("neuro-surprisal=19.9b")


def test_surprisal_term_is_capped_and_empty_without_scores():
    assert rs.neuro_surprisal({}, 100) == (0.0, "")
    pts, _ = rs.neuro_surprisal({"neuro_hdc_days": 1, "neuro_hdc_proto": 300.0}, 10)
    assert pts == rs.NEURO_CAP

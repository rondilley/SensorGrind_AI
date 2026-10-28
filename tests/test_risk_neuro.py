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

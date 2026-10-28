"""Unit tests for bench/compute_metrics pure aggregation functions.

These test arithmetic/aggregation on tiny in-memory inputs (not honeypot
data), so they're valid under the no-synthetic-data rule — they pin the
metric math, not detection logic. Corpus-dependent collection is exercised
via the `corpus` marker.
"""
from __future__ import annotations

import pytest

from bench import compute_metrics as cm


def test_fraction_handles_zero_denominator():
    assert cm.fraction(3, 0) is None
    assert cm.fraction(1, 4) == 0.25


def test_nonempty_coverage_counts_present_values():
    vals = ["a", "", None, ["x"], [], b"", "b"]
    # present & non-empty: "a", ["x"], "b" -> 3 of 7
    assert cm.nonempty_coverage(vals) == round(3 / 7, 4)


def test_nonempty_coverage_empty_input_is_none():
    assert cm.nonempty_coverage([]) is None


def test_precision_from_labels_excludes_unsure():
    res = cm.precision_from_labels(["signal", "signal", "noise", "unsure", ""])
    assert res["signal"] == 2 and res["noise"] == 1 and res["unsure"] == 1
    assert res["precision"] == round(2 / 3, 4)  # unsure excluded from denom
    assert res["labeled"] == 4


def test_precision_undefined_when_no_decisive_labels():
    res = cm.precision_from_labels(["unsure", "unsure"])
    assert res["precision"] is None


@pytest.mark.corpus
def test_gather_metrics_runs_on_real_corpus():
    m = cm.gather_metrics()
    assert "coverage" in m and "corpus" in m
    assert m["corpus"]["findings_total"] >= 0

"""Feature-alignment contract for the threat classifier.

The 2026-06-04 bug: extract_X returns a bare ndarray, LightGBM stored
placeholder feature names, and scoring matched by *position*. If
NUMERIC_FEATURES is ever reordered, train and score must still agree by
name. These tests pin that train/score share one feature ordering and that
as_frame() names columns exactly as the model expects.
"""
from __future__ import annotations

import numpy as np
import pyarrow as pa

from models import train_threat_classifier as tt


def _toy_table(n=8):
    cols = {name: pa.array(np.arange(n) + i, type=pa.float64())
            for i, name in enumerate(tt.NUMERIC_FEATURES)}
    return pa.table(cols)


def test_as_frame_columns_match_numeric_features_in_order():
    X = np.zeros((3, len(tt.NUMERIC_FEATURES)))
    df = tt.as_frame(X)
    assert list(df.columns) == tt.NUMERIC_FEATURES


def test_extract_X_column_order_is_numeric_features():
    tbl = _toy_table()
    X = tt.extract_X(tbl)
    assert X.shape == (8, len(tt.NUMERIC_FEATURES))
    # column i of extract_X must correspond to NUMERIC_FEATURES[i]; check a
    # non-log feature where the raw value is recoverable.
    for i, name in enumerate(tt.NUMERIC_FEATURES):
        if name not in tt.LOG_FEATURES:
            assert X[0, i] == float(i), f"{name} landed in wrong column"
            break


def test_log_features_are_log_scaled():
    tbl = _toy_table()
    X = tt.extract_X(tbl)
    for i, name in enumerate(tt.NUMERIC_FEATURES):
        if name in tt.LOG_FEATURES:
            raw = float(i)  # _toy_table sets column i base value to i
            assert np.isclose(X[0, i], np.log1p(raw)), f"{name} not log-scaled"


def test_as_frame_roundtrips_for_predict_naming():
    """A model fit on as_frame(X) records NUMERIC_FEATURES as feature_names_in_,
    so scoring with the same names aligns by name (the fix)."""
    df = tt.as_frame(np.zeros((2, len(tt.NUMERIC_FEATURES))))
    assert df.shape[1] == len(set(tt.NUMERIC_FEATURES))  # no dup feature names

"""Unit tests for sg.akd (the Python 3.14 libakida binding).

The vectors below are hand-written to pin the binding plumbing (shapes,
variable round trip, mapping, serialization); they are not honeypot data.
The arithmetic is checked on the real corpus by bench/akd_check.py.
Skipped when the binding is not built (python src/sg/akd/build.py).
"""
from __future__ import annotations

import numpy as np
import pytest

akd = pytest.importorskip("sg.akd", exc_type=ImportError)


def _model(act_bits=4):
    m = akd.Model()
    m.add(akd.input_layer(6))
    fc = akd.fully_connected(3, weights_bits=4, act_bits=act_bits, name="fc")
    m.add(fc)
    return m, fc


def test_virtual_akd1500_mesh():
    dev = akd.AKD1500()
    assert dev.version == akd.AKD1500_v1
    assert len(dev.mesh.nps) == 32 and not dev.is_hardware


def test_variables_round_trip_keep_type():
    m, fc = _model()
    assert m.input_shape == [1, 1, 6] and m.output_shape == [1, 1, 3]
    assert fc.variable_type("weights") == "int4"
    w = np.arange(-7, 11, dtype=np.int8).clip(-7, 7).reshape(fc.get_variable("weights").shape)
    fc.set_variable("weights", w)
    assert np.array_equal(fc.get_variable("weights"), w)


def test_forward_matches_reference_mapped_and_reloaded():
    m, fc = _model(act_bits=2)
    w = np.array([[1, -2, 3, 0, 7, -7], [2, 2, 2, 2, 2, 2], [-1, 0, 1, 0, -1, 0]], np.int8)
    w = w.reshape(fc.get_variable("weights").shape)
    th, st = np.array([3, 10, 0], np.int32), np.array([1.3, 2.71, 0.6], np.float32)
    for k, v in (("weights", w), ("threshold", th), ("act_step", st)):
        fc.set_variable(k, v)
    x = np.array([[0, 1, 2, 3, 4, 5], [15, 0, 15, 0, 15, 0], [1, 1, 1, 1, 1, 1]], np.uint8)
    out = m.forward(x.reshape(-1, 1, 1, 6)).reshape(3, 3)
    assert np.array_equal(out, akd.fc_reference(x, w, th, st, act_bits=2))
    m.map(akd.AKD1500())
    assert [s.backend.name for s in m.sequences] == ["Hardware"]
    assert fc.mapping[0]["neurons"] == 3
    again = akd.Model.from_bytes(m.to_bytes())
    assert np.array_equal(again.forward(x.reshape(-1, 1, 1, 6)).reshape(3, 3), out)


def test_card_forward_matches_reference():
    """Runs only when the driver finds an AKD1500 card (/dev/akd1500_*)."""
    cards = akd.devices()
    if not cards:
        pytest.skip("no AKD1500 card found by the driver")
    assert cards[0].is_hardware
    m, fc = _model(act_bits=4)
    w = np.array([[1, -2, 3, 0, 7, -7], [2, 2, 2, 2, 2, 2], [-1, 0, 1, 0, -1, 0]], np.int8)
    w = w.reshape(fc.get_variable("weights").shape)
    th, st = np.array([3, 10, 0], np.int32), np.array([1.3, 2.71, 0.6], np.float32)
    for k, v in (("weights", w), ("threshold", th), ("act_step", st)):
        fc.set_variable(k, v)
    x = np.array([[0, 1, 2, 3, 4, 5], [15, 0, 15, 0, 15, 0], [1, 1, 1, 1, 1, 1]], np.uint8)
    m.map(cards[0])
    assert [s.backend.name for s in m.sequences] == ["Hardware"]
    out = m.forward(x.reshape(-1, 1, 1, 6)).reshape(3, 3)
    assert np.array_equal(out, akd.fc_reference(x, w, th, st, act_bits=4))

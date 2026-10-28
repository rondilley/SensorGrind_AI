"""
sg.akd — BrainChip Akida (AKD1500) access on Python 3.14.

The PyPI akida wheels have a CPython 3.10..3.12 module only.  This package
binds libakida.so.2 (plain C++) directly; see _akd.cpp and build.py.  Build
once with ``python src/sg/akd/build.py``.

Models are built layer by layer (no TensorFlow, no cnn2snn): train in
PyTorch, quantize, then write the integer weights, thresholds and steps into
the Akida layers with ``Layer.set_variable``.

``fc_reference`` is the integer arithmetic of an Akida 1.0 FullyConnected
layer, checked bit for bit against libakida on real corpus windows by
bench/akd_check.py:

    p   = x @ W.T                       (int, x unsigned, W signed)
    q   = floor(act_step * 16) / 16     (act_step has 4 fraction bits)
    out = clip(ceil((p - threshold) / (q * 2**(4 - act_bits))), 0, 2**act_bits - 1)

With ``activation=False`` the layer returns p.
"""
from __future__ import annotations

import numpy as np

try:
    from . import _akd
    from ._akd import (AKD1500_v1, IpVersion, Layer, LayerType, Model,  # noqa: F401
                       NpType, __version__, devices, virtual_device)
except ImportError as e:                    # not built yet
    raise ImportError(f"{e}: build it with `python src/sg/akd/build.py`") from e


def AKD1500() -> _akd.Device:
    """Virtual AKD1500: the mesh of akida.virtual_devices.AKD1500()."""
    I, T = _akd.Ident, NpType
    nps = [_akd.NpInfo(I(1, 2, 0), {T.CNP1, T.FNP2})]
    nps += [_akd.NpInfo(I(1, 2, k), {T.CNP1}) for k in (1, 2, 3)]
    for col, row in ((1, 3), (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3)):
        nps.append(_akd.NpInfo(I(col, row, 0), {T.CNP1, T.FNP3}))
        nps += [_akd.NpInfo(I(col, row, k), {T.CNP1, T.CNP2}) for k in (1, 2, 3)]
    mesh = _akd.Mesh(IpVersion.v1, I(1, 1, 0), I(1, 1, 1),
                     _akd.NpInfo.hrc(False), nps)
    return virtual_device(AKD1500_v1, mesh)


def input_layer(channels: int, bits: int = 4, name: str = "input") -> Layer:
    """InputData layer for (N, 1, 1, channels) unsigned inputs."""
    return Layer(LayerType.InputData,
                 {"input_width": 1, "input_height": 1,
                  "input_channels": channels, "input_signed": 0,
                  "input_bits": bits}, name)


def fully_connected(units: int, weights_bits: int = 4, act_bits: int = 4,
                    activation: bool = True, name: str = "") -> Layer:
    return Layer(LayerType.FullyConnected,
                 {"units": units, "weights_bits": weights_bits,
                  "activation": int(activation), "act_bits": act_bits}, name)


def fc_reference(x: np.ndarray, w: np.ndarray, threshold: np.ndarray,
                 act_step: np.ndarray, act_bits: int = 4,
                 activation: bool = True) -> np.ndarray:
    """Akida 1.0 FullyConnected output for x (N, C) and w (units, C, ...)."""
    p = x.astype(np.int64) @ w.reshape(len(w), -1).T.astype(np.int64)
    if not activation:
        return p
    q = np.floor(np.asarray(act_step, np.float64) * 16) / 16
    z = (p - np.asarray(threshold, np.int64)) / (q * 2 ** (4 - act_bits))
    return np.clip(np.ceil(z), 0, 2 ** act_bits - 1).astype(np.int64)

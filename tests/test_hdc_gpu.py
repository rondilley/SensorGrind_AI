"""Unit tests for sg.hdc_gpu (GPU kernels of the HDC detectors).

The chains are hand-written token strings in chainfp's format (as in
test_hdc.py); they pin kernel equality with sg.hdc, not detection quality.
Real-day equality and timing: bench/hdc_gpu_check.py.  Skipped when
PyTorch sees no GPU.
"""
from __future__ import annotations

import numpy as np
import pytest

torch = pytest.importorskip("torch")
if not torch.cuda.is_available():
    pytest.skip("no GPU visible to PyTorch", allow_module_level=True)

from sg import hdc, hdc_gpu  # noqa: E402

D = 2048
CHAINS = ["****S*-TCP/3389~s,*A****-TCP/3389~1,*AP***-TCP/3389~0",
          "****S*-TCP/4444~s,*A****-TCP/4444~1,*AP***-TCP/4444~0",
          "****S*-TCP/3389~s,*A****-TCP/3389~1,*AP***-TCP/3389~3",
          "UDP/53~s,UDP/53~1",
          "UDP/53~s",
          "ICMP/8.0~s,ICMP/8.0~2,ICMP/8.0~2,ICMP/8.0~2",
          "****S*-TCP/22~s,****S*-TCP/23~0,****S*-TCP/80~0,****S*-TCP/443~0"]


def test_encode_bit_exact():
    enc = hdc.HDCEncoder(seed=3, d=D)
    assert np.array_equal(hdc_gpu.encode(enc, CHAINS), enc.encode(CHAINS))


def test_prototypes_and_proto_sim_match_cpu_without_ties():
    enc = hdc.HDCEncoder(seed=5, d=D)
    x = enc.encode(CHAINS)
    w = np.array([5, 1, 2, 7, 3, 1, 4], np.float32)
    k = 3
    cpu = hdc.prototypes(hdc.unit(x), w, k, seed=11)
    gpu = hdc_gpu.prototypes(x, w, k, seed=11)
    # with these few rows no centroid component sums to exactly 0, so the
    # float32 CPU path and the exact GPU path agree (with exact zeros the
    # CPU path rounds them to +/-1; see sg.hdc_gpu)
    assert np.array_equal(np.sign(cpu), np.sign(gpu.unit()))
    q = np.arange(len(x))
    b_gpu, a_gpu = hdc_gpu.proto_sim(x, q, [gpu])
    b_cpu, a_cpu = hdc.max_sim(x, cpu)
    assert np.array_equal(a_gpu, a_cpu)
    assert np.allclose(b_gpu, b_cpu, atol=1e-6)


def test_prototypes_small_input_returns_rows():
    enc = hdc.HDCEncoder(seed=5, d=D)
    x = enc.encode(CHAINS[:2])
    c = hdc_gpu.prototypes(x, np.ones(2, np.float32), 4, seed=1)
    assert np.allclose(c.unit(), hdc.unit(x))

"""Unit tests for bench/akd_h1 (AKD1500 model H1).

Hand-written rows pin the port / flag classes and the export of the
quantization-aware network; they are not honeypot data.  H1 is trained and
scored only on the real corpus plus injection sets (bench/akd_h1.py).
"""
from __future__ import annotations

import duckdb
import numpy as np
import pytest

from bench import akd_h1 as h

torch = pytest.importorskip("torch")
akd = pytest.importorskip("sg.akd", exc_type=ImportError)


@pytest.mark.parametrize("port, cls", [(22, 0), (2323, 1), (8080, 2), (445, 4), (3389, 5),
                                       (123, 9), (999, 12), (5000, 13), (20000, 14)])
def test_port_class(port, cls):
    assert duckdb.sql(f"SELECT {h.PORT_SQL} FROM (SELECT {port} dst_port)").fetchone()[0] == cls


@pytest.mark.parametrize("proto, flags, slot", [(6, 0x02, 0), (6, 0x10, 1), (6, 0x18, 2),
                                                (6, 0x14, 3), (6, 0x11, 4), (6, 0x12, 5),
                                                (17, None, 6), (1, None, 7)])
def test_flag_class(proto, flags, slot):
    f = "NULL::UTINYINT" if flags is None else flags
    q = f"SELECT {h.FLAG_SQL} FROM (SELECT {proto} proto, {f} tcp_flags)"
    assert duckdb.sql(q).fetchone()[0] == slot


def test_encode_is_uint4_log2():
    assert h.encode(np.array([0, 1, 3, 7, 10**6])).tolist() == [0, 1, 2, 3, 15]


def test_qat_forward_equals_exported_integers():
    torch.manual_seed(0)
    QNet, _ = h.build_nets(5)
    net = QNet()
    with torch.no_grad():
        for layer in net.layers:
            layer.log_step.fill_(0.5)
    x = np.array([[i % 16 for i in range(j, j + h.N_IN)] for j in range(8)], np.uint8)
    with torch.no_grad():
        lg = net(torch.tensor(x, dtype=torch.float32)).numpy()
    layers = h.export_ints(net)
    q = h.quant_logits(layers, x)
    assert np.allclose(lg, q, atol=1e-4)
    m = h.akida_model(layers)
    assert np.array_equal(h.akida_logits(m, layers, x), q)

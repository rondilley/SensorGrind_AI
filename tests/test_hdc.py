"""Unit tests for sg.hdc (neuromorphic plan Phase 1 encoder).

The chains below are hand-written token strings in chainfp's format, used to
pin encoder properties (determinism, graded similarity, exact 1-NN); they are
not honeypot data and no detector result depends on them.  Detection quality
is measured only on the real corpus by bench/hdc_eval.py.
"""
from __future__ import annotations

import numpy as np
import pytest

from sg import hdc

D = 2048
RDP = "****S*-TCP/3389~s,*A****-TCP/3389~1,*AP***-TCP/3389~0"
RDP_PORT = "****S*-TCP/4444~s,*A****-TCP/4444~1,*AP***-TCP/4444~0"
RDP_TEMPO = "****S*-TCP/3389~s,*A****-TCP/3389~1,*AP***-TCP/3389~3"
DNS = "UDP/53~s,UDP/53~1"


def _cos(a, b):
    a, b = a.astype(float), b.astype(float)
    return a @ b / (np.linalg.norm(a) * np.linalg.norm(b))


def test_split_token_fields():
    assert hdc.split_token("****S*-TCP/3389~1") == ("****S*", "TCP/3389", "1")
    assert hdc.split_token("UDP/53~s") == ("UDP", "UDP/53", "s")
    assert hdc.split_token("ICMP/8.0") == ("ICMP", "ICMP/8.0", "-")
    assert hdc.split_token("proto-47~2") == ("proto-47", "proto-47", "2")


def test_encode_is_deterministic_and_bipolar():
    a = hdc.HDCEncoder(seed=7, d=D).encode([RDP, DNS])
    b = hdc.HDCEncoder(seed=7, d=D).encode([DNS, RDP])
    assert a.dtype == np.int8 and set(np.unique(a)) == {-1, 1}
    assert (a[0] == b[1]).all() and (a[1] == b[0]).all()
    c = hdc.HDCEncoder(seed=8, d=D).encode([RDP])
    assert abs(_cos(a[0], c[0])) < 0.15          # other seed: unrelated


def test_similarity_is_graded():
    v = hdc.HDCEncoder(seed=1, d=D).encode([RDP, RDP_TEMPO, RDP_PORT, DNS])
    tempo, port, other = (_cos(v[0], v[i]) for i in (1, 2, 3))
    assert tempo > port > other
    assert port > 5 / np.sqrt(D)                  # above the noise floor


def test_field_memory_matches_explicit_token_bundle():
    enc = hdc.HDCEncoder(seed=3, d=D)
    tokens = ["****S*-TCP/22~s", "UDP/53~1"]
    fv, tf, tp, tm = enc.field_memory(tokens)
    for t in range(len(tokens)):
        explicit = np.sign(fv[tf[t]].astype(int) + fv[tp[t]] + fv[tm[t]])
        one_tok = enc.encode([tokens[t]])[0]      # unigram only = the token
        assert (explicit == one_tok).all()


def test_max_sim_matches_brute_force_with_index_and_chunks():
    rng = np.random.default_rng(0)
    mem = rng.choice(np.array([-1, 1], dtype=np.int8), size=(300, 256))
    q = mem[[5, 77, 250]].copy()
    q[0, :40] *= -1                               # near-miss of row 5
    idx = np.arange(0, 300, 2)                    # even rows only
    best, arg = hdc.max_sim(q, mem, idx, chunk=2, mem_chunk=16)
    full = hdc.unit(q) @ hdc.unit(mem[idx]).T
    assert np.allclose(best, full.max(axis=1), atol=1e-6)
    assert (arg == full.argmax(axis=1)).all()
    assert idx[arg[2]] == 250 and best[2] == pytest.approx(1.0)


def test_floor_noise():
    tau = 5 / np.sqrt(D)
    out = hdc.floor_noise(np.array([0.0, tau, 1.0, (1 + tau) / 2]), D)
    assert out[:3].tolist() == [0.0, 0.0, 1.0]
    assert out[3] == pytest.approx(0.5)


def test_prototypes_are_unit_bipolar_bundles():
    v = hdc.unit(hdc.HDCEncoder(seed=1, d=D).encode(
        [RDP, RDP_TEMPO, RDP_PORT, DNS, "UDP/53~s,UDP/53~0"]))
    p = hdc.prototypes(v, np.ones(len(v), dtype=np.float32), k=2, seed=0)
    assert p.shape == (2, D)
    assert np.allclose(np.linalg.norm(p, axis=1), 1.0, atol=1e-5)


def test_prototypes_without_binarize_are_mean_directions():
    # the rff_proto twin: plain weighted spherical k-means, no sign step
    r = hdc.unit(hdc.rff_encode([RDP, RDP_TEMPO, RDP_PORT, DNS,
                                 "UDP/53~s,UDP/53~0"], seed=1, d=512))
    w = np.ones(len(r), dtype=np.float32)
    p = hdc.prototypes(r, w, k=2, seed=0, binarize=False)
    assert p.shape == (2, 512)
    assert np.allclose(np.linalg.norm(p, axis=1), 1.0, atol=1e-5)
    assert len(np.unique(np.abs(p).round(6))) > 2      # not sign vectors
    _, a = hdc.max_sim(r, p)
    for j in range(2):
        m = r[a == j].sum(axis=0)
        assert p[j] @ (m / np.linalg.norm(m)) == pytest.approx(1.0, abs=1e-4)


def test_rff_twin_shape_and_identity():
    r = hdc.unit(hdc.rff_encode([RDP, RDP, DNS], seed=1, d=512))
    assert r.shape == (3, 512)
    assert r[0] @ r[1] == pytest.approx(1.0, abs=1e-5)
    assert r[0] @ r[2] < 0.9


def test_max_sim_packed_bits_equal_float_product():
    # int8 inputs take the packed Hamming path; the float32 path is the
    # reference: same cosine, same best row (first row on ties)
    v = hdc.HDCEncoder(seed=2, d=D).encode([RDP, RDP_TEMPO, RDP_PORT, DNS])
    mem = np.vstack([v, v[:1]])           # a duplicate row: a tie
    q = v[[0, 2, 3]]
    bp, ap = hdc.max_sim(q, mem)
    bf, af = hdc.max_sim(q.astype(np.float32), mem.astype(np.float32))
    assert np.allclose(bp, bf, atol=1e-6)
    assert (ap == af).all() and ap[0] == 0
    assert hdc.pack_bits(v).shape == (4, D // 64)

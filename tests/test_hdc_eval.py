"""Unit tests for the round-2 alignment score in bench/hdc_eval.py.

The chains are hand-written token strings in chainfp's format that pin the
score's arithmetic; they are not honeypot data, and no gate number depends
on them.
"""
from __future__ import annotations

import numpy as np

import scipy.sparse as sp

from bench import hdc_eval as he
from sg import hdc

A = "****S*-TCP/22~s,*A****-TCP/22~1,*AP***-TCP/22~0"
B = "****S*-TCP/80~s,***R**-TCP/80~1"
B2 = "****S*-TCP/45555~s,***R**-TCP/45555~1"     # B on a new port
C = "UDP/53~s,UDP/53~1"


def _case(d_chains):
    fit = [("10.0.0.1", 1, A), ("10.0.0.1", 1, B), ("10.0.0.2", 1, C)]
    rows = fit + [("10.9.9.9", 2, c) for c in d_chains]
    ip, day, ch = map(list, zip(*rows))
    uniq = sorted(set(ch))
    sid = np.array([uniq.index(c) for c in ch])
    iid = np.array([sorted(set(ip)).index(x) for x in ip])
    di = np.array(day)
    fm, _ = he._src_days(sid, iid, di, di == 1, len(uniq), "distinct")
    dm, _ = he._src_days(sid, iid, di, di == 2, len(uniq), "distinct")
    v = hdc.HDCEncoder(1, 2048).encode(uniq)
    f = v.astype(np.float32) / np.sqrt(2048)
    h = he._align(v, dm, fm, 4.0, 1.0 / 2048)[0]
    assert abs(h - he._align(f, dm, fm, 4.0)[0]) < 1e-5   # int8 == float
    return (h, he._align(None, dm, fm, 4.0)[0])


def test_exact_replay_scores_zero():
    h, s = _case([A, B])
    assert abs(h) < 1e-5 and s == 0.0


def test_changed_port_scores_above_replay_and_unrelated():
    mut_h, mut_s = _case([A, B2])
    unrel_h, _ = _case(["ICMP/8.0~s,ICMP/8.0~1"])
    assert abs(mut_s - 0.5 ** 4) < 1e-6         # bags share 1 of 2 chains
    assert mut_h > 0.05
    assert mut_h > unrel_h


def _rand_csr(rng, rows, cols, nnz):
    m = sp.csr_matrix((np.ones(nnz, np.float32),
                       (rng.integers(0, rows, nnz), rng.integers(0, cols, nnz))),
                      shape=(rows, cols))
    m.sum_duplicates()
    return m


def test_bundles_in_chunks_equal_whole_product(monkeypatch):
    rng = np.random.default_rng(0)
    v = rng.choice(np.array([-1, 1], np.int8), size=(5000, 256))
    m = _rand_csr(rng, 300, 5000, 4000)
    monkeypatch.setattr(he, "BUNDLE_NNZ", 64)       # force many chunks
    out = np.empty((300, 256), np.float32)
    he._bundles(m, v, out)
    assert np.array_equal(out, he._rownorm(m @ v))  # bitwise


def test_worst_dev_blocks_equal_one_product(monkeypatch):
    rng = np.random.default_rng(1)
    v = rng.standard_normal((3000, 64)).astype(np.float32)
    xc, yc = np.arange(0, 900), np.arange(800, 3000)
    whole = he._worst_dev(v, xc, yc)
    monkeypatch.setattr(he, "XY_CELLS", 5000)       # force blocks
    assert he._worst_dev(v, xc, yc) == whole


def test_max_sim_q_idx_equals_fancy_index():
    rng = np.random.default_rng(2)
    mem = rng.choice(np.array([-1, 1], np.int8), size=(4000, 128))
    q_idx = rng.choice(4000, 700)
    idx = np.arange(0, 4000, 3)
    a = hdc.max_sim(mem[q_idx], mem, idx, chunk=64, mem_chunk=512)
    b = hdc.max_sim(mem, mem, idx, chunk=64, mem_chunk=512, q_idx=q_idx)
    assert np.array_equal(a[0], b[0]) and np.array_equal(a[1], b[1])


def test_per_source_max_and_zero_default():
    pop_of = np.array([0, -1, 2])                   # source 1 is not scored
    out = he._per_source(pop_of, 4, np.array([0, 0, 1, 2]),
                         [-3.0, -1.0, 9.0, -2.0])
    assert out.tolist() == [-1.0, 0.0, -2.0, 0.0]

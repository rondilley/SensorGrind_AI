"""Unit tests for sg/context (proposal A1): the context codes and the merge of
small strata into their parent.  The arrays are hand-written to pin the
arithmetic; they are not honeypot data."""
from __future__ import annotations

import numpy as np

from sg import context, lif


def test_port_and_l7_classes():
    assert context.port_class([0, 1, 2, 10, 11]).tolist() == [0, 0, 1, 1, 2]
    from sg import lib
    ids = [None, 0, lib.L7_ID["http"], lib.L7_ID["bittorrent"], lib.L7_ID["mqtt"]]
    assert context.l7_class(ids).tolist() == [0, 0, 1, 5, context.L7_OTHER]


def test_asn_class_scanner_first_then_keywords():
    assert context.asn_class("Comcast Cable", True) == context.ASN_SCANNER
    assert context.asn_class("DIGITALOCEAN-ASN", False) == context.ASN_HOSTING
    assert context.asn_class("Charter Communications Inc", False) == context.ASN_RESIDENTIAL
    assert context.asn_class(None, False) == context.ASN_OTHER


def test_align_fills_missing_sources_with_zeros():
    ctx = np.array([[1, 2, 3, 0], [2, 1, 0, 1]], dtype=np.int8)
    out = context.align(["b", "x", "a"], ["a", "b"], ctx)
    assert out.tolist() == [[2, 1, 0, 1], [0, 0, 0, 0], [1, 2, 3, 0]]


def test_calibrate_ctx_uses_the_stratum_when_it_is_large_enough():
    rng = np.random.default_rng(0)
    n = 4000
    # stratum A (code 1000) has scores near 0, stratum B (2000) near 10
    ref_ctx = np.zeros((2 * n, 4), dtype=np.int8)
    ref_ctx[:n, 0], ref_ctx[n:, 0] = 1, 2
    ref = np.r_[rng.normal(0, 1, n), rng.normal(10, 1, n)]
    ref_logn = np.zeros(2 * n)
    score = np.array([5.0, 5.0])
    ctx = np.array([[1, 0, 0, 0], [2, 0, 0, 0]], dtype=np.int8)
    out, level = context.calibrate_ctx(score, np.zeros(2), ctx, ref, ref_logn,
                                       ref_ctx, min_ref=n)
    assert level.tolist() == [4, 4]
    assert out[0] > 4 and out[1] < 0.1      # rare in A, common in B
    plain = lif.calibrate(score, np.zeros(2), ref, ref_logn)
    assert plain[0] == plain[1]


def test_calibrate_ctx_merges_a_small_stratum_into_its_parent():
    ref_ctx = np.zeros((100, 4), dtype=np.int8)
    ref_ctx[:, 0] = 1
    ref_ctx[:10, 1] = 3                     # (1, 3) has 10 rows only
    ref = np.arange(100, dtype=float)
    ctx = np.array([[1, 3, 0, 0]], dtype=np.int8)
    out, level = context.calibrate_ctx(np.array([50.0]), np.zeros(1), ctx, ref,
                                       np.zeros(100), ref_ctx, min_ref=50)
    assert level.tolist() == [1]            # port class only
    assert out[0] == lif.calibrate(np.array([50.0]), np.zeros(1), ref,
                                   np.zeros(100))[0]


def test_calibrate_ctx_falls_back_to_all_reference_rows():
    ref_ctx = np.zeros((20, 4), dtype=np.int8)
    ctx = np.array([[2, 1, 1, 1]], dtype=np.int8)
    ref = np.arange(20, dtype=float)
    out, level = context.calibrate_ctx(np.array([10.0]), np.zeros(1), ctx, ref,
                                       np.zeros(20), ref_ctx, min_ref=1000)
    assert level.tolist() == [0]
    assert out[0] == lif.calibrate(np.array([10.0]), np.zeros(1), ref,
                                   np.zeros(20))[0]


def test_neuro_ctx_codes_round_trip():
    import neuro
    ctx = np.array([[2, 6, 3, 1], [0, 0, 0, 0], [1, 5, 2, 0]], dtype=np.int8)
    assert neuro.ctx_codes(context._keys(ctx, 4)).tolist() == ctx.tolist()

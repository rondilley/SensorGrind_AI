"""
sg.hdc_gpu — GPU (ROCm / CUDA PyTorch) kernels for the HDC detectors.

Same model as sg.hdc; only the arithmetic moves to the GPU.

``encode``      HDCEncoder.encode on the GPU.  Integer arithmetic only, so
                the rows are bit for bit those of the numba kernel
                (checked by bench/hdc_gpu_check.py).
``prototypes``  hdc.prototypes(unit(x), w, k, seed) for bipolar x.  A
                centroid is kept as its sign row s in {-1, 0, +1}; its unit
                vector is (s + 1e-3 * [s == 0]) / norm, as in hdc.prototypes.
                Cosines come from exact integer dot products (fp16 matmuls
                over 2048-column blocks: every partial sum is an integer of
                at most 2048, which fp16 holds exactly) and are combined in
                float64.  The CPU path rounds in float32, so a near tie in
                the nearest-centroid step can go the other way: prototypes
                and scores are close to, not identical with, the CPU ones.
``proto_sim``   hdc.max_sim(x, unit prototypes) for bipolar queries, with
                the same exact dot products.

Bipolar rows are int8 +/-1 (numpy in, numpy out).
"""
from __future__ import annotations

import numpy as np
import torch

from . import hdc

K_BLOCK = 2048                     # fp16 holds every integer up to 2048
ROW_CHUNK = 16384                  # rows per GPU block
POS_CHUNK = 4096                   # n-gram positions per scatter-add
ZERO_W = 1e-3                      # weight of a tied centroid component


def device() -> torch.device:
    if not torch.cuda.is_available():
        raise RuntimeError("sg.hdc_gpu: no GPU visible to PyTorch")
    return torch.device("cuda")


# ---------------------------------------------------------------- encode

def encode(enc: hdc.HDCEncoder, chains: list[str]) -> np.ndarray:
    """int8 +/-1 matrix, one row per chain; equal to ``enc.encode``."""
    dev = device()
    voc = hdc._Vocab()
    offsets, ids = voc.pack(chains)
    fv, tf, tp, tm = enc.field_memory(voc.tokens())
    fv_t = torch.from_numpy(fv).to(dev)
    # token vector = sign of its three role-bound fields (never 0)
    tv = (fv_t[torch.from_numpy(tf).to(dev)].to(torch.int16)
          + fv_t[torch.from_numpy(tp).to(dev)]
          + fv_t[torch.from_numpy(tm).to(dev)])
    tv = (tv > 0).to(torch.int8) * 2 - 1
    del fv_t
    # component j of a token shifted by s is token[(j - s) % d]
    rolled = [tv] + [torch.roll(tv, s, dims=1) for s in range(1, enc.n)]
    rows = len(chains)
    length = np.diff(offsets)
    row_of = np.repeat(np.arange(rows), length)
    end_of = offsets[1:][row_of]
    ids_t = torch.from_numpy(ids).to(dev)
    acc = torch.zeros((rows, enc.d), dtype=torch.int32, device=dev)
    for ne in range(1, enc.n + 1):
        start = np.flatnonzero(np.arange(len(ids)) + ne <= end_of)
        for a in range(0, len(start), POS_CHUNK):
            p = torch.from_numpy(start[a:a + POS_CHUNK]).to(dev)
            # position q of the n-gram is shifted by (ne - 1 - q)
            g = rolled[ne - 1][ids_t[p]].to(torch.int32)
            for q in range(1, ne):
                g *= rolled[ne - 1 - q][ids_t[p + q]]
            acc.index_add_(0, torch.from_numpy(row_of[start[a:a + POS_CHUNK]]).to(dev), g)
    tie = torch.from_numpy(enc.tie).to(dev).expand(rows, -1)
    out = torch.sign(acc).to(torch.int8)
    out = torch.where(out == 0, tie, out)
    return out.cpu().numpy()


# ---------------------------------------------------------------- similarity

def _dots(x16: torch.Tensor, c16: torch.Tensor) -> torch.Tensor:
    """Exact integer x @ c.T (float64) for fp16 rows with entries in
    {-1, 0, 1}."""
    out = torch.zeros((len(x16), len(c16)), dtype=torch.float64, device=x16.device)
    for j in range(0, x16.shape[1], K_BLOCK):
        out += (x16[:, j:j + K_BLOCK] @ c16[:, j:j + K_BLOCK].T).to(torch.float64)
    return out


class _Centroids:
    """Sign rows s; unit vector (s + ZERO_W * [s == 0]) / norm."""

    def __init__(self, s: torch.Tensor):
        self.s16 = s.to(torch.float16)
        self.z16 = (s == 0).to(torch.float16)
        nz = self.z16.sum(1, dtype=torch.float64)
        self.norm = torch.sqrt(s.shape[1] - nz + ZERO_W ** 2 * nz)
        self.has_zero = bool(nz.any())

    def cos(self, x16: torch.Tensor) -> torch.Tensor:
        """Cosine of bipolar fp16 rows against each centroid."""
        num = _dots(x16, self.s16)
        if self.has_zero:
            num += ZERO_W * _dots(x16, self.z16)
        return num / (np.sqrt(x16.shape[1]) * self.norm)

    def unit(self) -> np.ndarray:
        v = self.s16.to(torch.float64) + ZERO_W * self.z16.to(torch.float64)
        return (v / self.norm[:, None]).to(torch.float32).cpu().numpy()


def _best(x: torch.Tensor, cents: _Centroids) -> tuple[torch.Tensor, torch.Tensor]:
    best, arg = [], []
    for a in range(0, len(x), ROW_CHUNK):
        sim = cents.cos(x[a:a + ROW_CHUNK].to(torch.float16))
        b, i = sim.max(dim=1)                  # first index of the maximum
        best.append(b)
        arg.append(i)
    return torch.cat(best), torch.cat(arg)


def prototypes(x: np.ndarray, w: np.ndarray, k: int, seed: int,
               iters: int = 10) -> _Centroids:
    """hdc.prototypes(hdc.unit(x), w, k, seed, binarize=True) for int8
    bipolar ``x``; returns the centroids (``.unit()`` gives the rows)."""
    dev = device()
    xt = torch.from_numpy(np.ascontiguousarray(x)).to(dev)
    if len(x) <= k:
        return _Centroids(xt.clone())
    rng = np.random.default_rng(seed)
    p = np.asarray(w, dtype=np.float64)
    c = xt[torch.from_numpy(rng.choice(len(x), k, replace=False, p=p / p.sum())).to(dev)]
    wt = torch.from_numpy(np.asarray(w).astype(np.int64)).to(dev)
    for _ in range(iters):
        cents = _Centroids(c)
        _, a = _best(xt, cents)
        nc = torch.zeros((k, x.shape[1]), dtype=torch.int64, device=dev)
        for s in range(0, len(x), ROW_CHUNK):
            nc.index_add_(0, a[s:s + ROW_CHUNK],
                          xt[s:s + ROW_CHUNK].to(torch.int64) * wt[s:s + ROW_CHUNK, None])
        empty = ~nc.any(dim=1)
        new = torch.sign(nc).to(torch.int8)
        # hdc.prototypes keeps the old unit row of an empty cluster, whose
        # tied components (ZERO_W / norm > 0) then re-binarize to +1
        new[empty] = torch.where(c[empty] == 0, 1, c[empty]).to(torch.int8)
        c = new
    return _Centroids(c)


def proto_sim(vecs, q_idx: np.ndarray, protos: list[_Centroids]
              ) -> tuple[np.ndarray, np.ndarray]:
    """Best cosine of each row ``vecs[q_idx]`` against all prototypes, and
    its position in the stacked prototype rows (hdc.max_sim layout)."""
    dev = device()
    n = len(q_idx)
    if not protos:
        return np.full(n, -1.0, np.float32), np.full(n, -1, np.int64)
    cents = _Centroids(torch.cat([c.s16 for c in protos]).to(torch.int8))
    best = np.empty(n, np.float32)
    arg = np.empty(n, np.int64)
    for a in range(0, n, ROW_CHUNK):
        x = torch.from_numpy(np.asarray(vecs[q_idx[a:a + ROW_CHUNK]])).to(dev)
        b, i = _best(x, cents)
        best[a:a + len(x)] = b.cpu().numpy()
        arg[a:a + len(x)] = i.cpu().numpy()
    return best, arg

"""
sg.stdp — winner-take-all STDP prototypes of destination-port "retinas".

Neuromorphic plan Phase 5 (docs/ARCHITECTURE.md §9.1).  A source-day is a
retina: N_BINS input neurons, one per destination-port hash bucket (the
Knuth hash of bench/arrival_series, wider), each with the source's packet
share on that bucket.  K output neurons compete:

  * activation  a_j = <x, w_j> - theta_j      (x and w_j have unit norm)
  * the winner j* = argmax a_j fires (winner-take-all lateral inhibition)
  * STDP for the winner only: inputs that fired before the output spike
    are potentiated, the others are depressed,
        w_j* <- normalize(w_j* + eta * (x - w_j*))
  * homeostasis: theta_j* += theta_plus, every theta decays by
    (1 - 1 / tau_theta), so no output neuron takes every input
    (Diehl & Cook 2015)

The novelty of a retina is 1 - max_j <x, w_j>: no learned prototype looks
like this port mix.  ``eta = 0`` gives the untrained copy (prototypes stay
at their initial values, K random fit retinas).
"""
from __future__ import annotations

import numpy as np
from numba import njit

N_BINS = 4096
K = 256
ETA = 0.05
THETA_PLUS = 0.02
TAU_THETA = 2000.0
EPOCHS = 2


def port_bins(port: np.ndarray) -> np.ndarray:
    """Knuth multiplicative hash of a 16-bit port into N_BINS buckets."""
    return ((port.astype(np.int64) * 40503) % 65536) * N_BINS // 65536


def retinas(owner: np.ndarray, port: np.ndarray, cnt: np.ndarray, n_src: int
            ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """CSR (indptr, bins, values) of unit-norm packet-share retinas.
    ``owner`` must be sorted."""
    b = port_bins(port)
    key = owner.astype(np.int64) * N_BINS + b
    order = np.argsort(key, kind="stable")
    key, c = key[order], cnt[order].astype(np.float64)
    uk, start = np.unique(key, return_index=True)
    val = np.add.reduceat(c, start) if len(c) else c
    own = uk // N_BINS
    bins = (uk % N_BINS).astype(np.int64)
    indptr = np.searchsorted(own, np.arange(n_src + 1))
    norm = np.sqrt(np.bincount(own, val ** 2, minlength=n_src))
    return indptr, bins, val / np.maximum(norm[own], 1e-12)


@njit(cache=True)
def _train(indptr, bins, vals, order, w, eta, theta_plus, tau_theta, epochs):
    K, B = w.shape
    theta = np.zeros(K)
    decay = 1.0 - 1.0 / tau_theta
    for _ in range(epochs):
        for r in order:
            a, b = indptr[r], indptr[r + 1]
            if a == b:
                continue
            best, bj = -1e300, 0
            for j in range(K):
                s = 0.0
                for x in range(a, b):
                    s += w[j, bins[x]] * vals[x]
                s -= theta[j]
                if s > best:
                    best, bj = s, j
            if eta > 0.0:
                for i in range(B):
                    w[bj, i] *= 1.0 - eta
                for x in range(a, b):
                    w[bj, bins[x]] += eta * vals[x]
                nrm = 0.0
                for i in range(B):
                    nrm += w[bj, i] * w[bj, i]
                nrm = np.sqrt(nrm)
                if nrm > 0:
                    for i in range(B):
                        w[bj, i] /= nrm
            for j in range(K):
                theta[j] *= decay
            theta[bj] += theta_plus
    return w


@njit(cache=True)
def _novelty(indptr, bins, vals, w):
    K = w.shape[0]
    n = len(indptr) - 1
    out = np.ones(n)
    for r in range(n):
        a, b = indptr[r], indptr[r + 1]
        if a == b:
            continue
        best = -1.0
        for j in range(K):
            s = 0.0
            for x in range(a, b):
                s += w[j, bins[x]] * vals[x]
            if s > best:
                best = s
        out[r] = 1.0 - best
    return out


def init_prototypes(indptr, bins, vals, k: int = K, seed: int = 0) -> np.ndarray:
    """K random fit retinas as the initial (dense) prototypes."""
    rng = np.random.default_rng(seed)
    n = len(indptr) - 1
    pick = rng.choice(n, size=min(k, n), replace=False)
    w = np.zeros((len(pick), N_BINS))
    for j, r in enumerate(pick):
        a, b = indptr[r], indptr[r + 1]
        w[j, bins[a:b]] = vals[a:b]
    return w


def train(indptr, bins, vals, w0: np.ndarray, eta: float = ETA,
          theta_plus: float = THETA_PLUS, tau_theta: float = TAU_THETA,
          epochs: int = EPOCHS, seed: int = 0) -> np.ndarray:
    order = np.random.default_rng(seed).permutation(len(indptr) - 1)
    return _train(indptr, bins, vals, order, w0.copy(), float(eta),
                  float(theta_plus), float(tau_theta), int(epochs))


def novelty(indptr, bins, vals, w: np.ndarray) -> np.ndarray:
    return _novelty(indptr, bins, vals, np.ascontiguousarray(w))

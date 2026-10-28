"""
sg.hdc — hyperdimensional (HDC) encoding of chainfp session chains.

Neuromorphic plan Phase 1 (docs/ARCHITECTURE.md §9).  A session chain such as

    ****S*-TCP/3389~s,*A****-TCP/3389~1,*AP***-TCP/3389~0

becomes one bipolar (MAP) hypervector, so two sessions have a *graded*
similarity instead of the all-or-nothing string match that chainfp's
anomaly tiers use.

Encoding
--------
- Each token splits into three fields: ``flags`` (the TCP flag mask, or the
  protocol name for UDP/ICMP/other), ``port`` (``TCP/3389``, ``UDP/53``,
  ``ICMP/8.0``) and ``tempo`` (the chainfp tempo bucket s/0/1/2/3).
- token = sign(F*R_f + P*R_p + M*R_t): each field value is bound (elementwise
  product) to a role vector and the three are bundled.  Two tokens that
  share two fields keep ~0.5 cosine, so "same handshake, other port" stays
  near its source instead of becoming a brand-new string.
- session = sign(sum of all 1-, 2- and 3-grams), n-gram = rho^2(t_i) *
  rho(t_i+1) * t_i+2 (rho = cyclic shift).  Binding multiplies similarity,
  so a trigram of three ~0.5-similar tokens keeps only ~0.13; the unigram and
  bigram terms keep the graded similarity.  Ties go to a fixed seeded vector.

Item vectors are generated from a 64-bit hash of (seed, field, value), so no
item memory is stored and every run with the same seed is identical.

``rff_encode`` is the classical twin used as a baseline: the same n-grams,
hashed as whole tokens (no field structure), Gaussian random projection,
then random Fourier features of the L2-normalized n-gram count vector.
"""
from __future__ import annotations

import hashlib

import numpy as np
from numba import njit, prange

D_DEFAULT = 8192
NGRAM = 3


def key64(*parts: object) -> int:
    """Stable 64-bit key (blake2b), independent of PYTHONHASHSEED."""
    h = hashlib.blake2b("\x1f".join(map(str, parts)).encode(), digest_size=8)
    return int.from_bytes(h.digest(), "little")


def split_token(tok: str) -> tuple[str, str, str]:
    """``****S*-TCP/3389~1`` -> (``****S*``, ``TCP/3389``, ``1``).

    Untimed tokens get tempo ``-``; non-TCP tokens use the protocol name as
    the flags field (``UDP/53`` -> ``UDP``)."""
    body, _, tempo = tok.partition("~")
    flags, sep, port = body.partition("-")
    if not sep or not port or flags == "proto":   # UDP/53, ICMP/8.0, proto-47
        port = body
        flags = body.split("/", 1)[0]
    return flags, port, tempo or "-"


# ---------------------------------------------------------------- kernels

@njit(cache=True, inline="always")
def _splitmix(x):
    x = (x + np.uint64(0x9E3779B97F4A7C15))
    z = x
    z = (z ^ (z >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
    z = (z ^ (z >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
    return x, z ^ (z >> np.uint64(31))


@njit(cache=True, parallel=True)
def _bipolar_rows(keys, d):
    """One +/-1 int8 row per uint64 key."""
    out = np.empty((len(keys), d), dtype=np.int8)
    for r in prange(len(keys)):
        s = keys[r]
        j = 0
        while j < d:
            s, z = _splitmix(s)
            for b in range(64):
                if j >= d:
                    break
                out[r, j] = 1 if (z >> np.uint64(b)) & np.uint64(1) else -1
                j += 1
    return out


@njit(cache=True, inline="always")
def _tok(fv, tf, tp, tm, t, j):
    """Component j of token t: sign of its three role-bound field vectors
    (a sum of three +/-1 terms is never 0)."""
    return 1 if fv[tf[t], j] + fv[tp[t], j] + fv[tm[t], j] > 0 else -1


@njit(cache=True, parallel=True)
def _encode(fv, tf, tp, tm, offsets, ids, tie, n):
    """Bundle the rho-permuted 1..n-grams of each row (CSR ``offsets``/``ids``).

    Token vectors are made on the fly from the field item memory ``fv``:
    a day holds ~3e5 distinct tokens but only ~6e4 distinct field values, so
    a token matrix would cost 5x the memory (16 GB at D = 8192)."""
    rows = len(offsets) - 1
    d = fv.shape[1]
    out = np.empty((rows, d), dtype=np.int8)
    for r in prange(rows):
        a, b = offsets[r], offsets[r + 1]
        length = b - a
        acc = np.zeros(d, dtype=np.int32)
        for ne in range(1, min(n, length) + 1):
            for i in range(a, b - ne + 1):
                for j in range(d):
                    g = 1
                    for q in range(ne):
                        # position q of the n-gram is shifted by (ne-1-q)
                        g *= _tok(fv, tf, tp, tm, ids[i + q],
                                  (j - (ne - 1 - q)) % d)
                    acc[j] += g
        for j in range(d):
            v = acc[j]
            out[r, j] = 1 if v > 0 else (-1 if v < 0 else tie[j])
    return out


@njit(cache=True, inline="always")
def _gauss_pair(s):
    s, z1 = _splitmix(s)
    s, z2 = _splitmix(s)
    u1 = ((z1 >> np.uint64(11)) + np.uint64(1)) * (1.0 / 9007199254740993.0)
    u2 = (z2 >> np.uint64(11)) * (1.0 / 9007199254740992.0)
    r = np.sqrt(-2.0 * np.log(u1))
    return s, r * np.cos(2.0 * np.pi * u2), r * np.sin(2.0 * np.pi * u2)


@njit(cache=True, parallel=True)
def _rff(tok_keys, offsets, ids, n, phase, sigma):
    """sqrt(2/D) cos(W x / sigma + phase), x = L2-normalized n-gram counts."""
    rows = len(offsets) - 1
    d = len(phase)
    out = np.empty((rows, d), dtype=np.float32)
    for r in prange(rows):
        a, b = offsets[r], offsets[r + 1]
        ne = min(n, b - a)
        m = (b - a - ne + 1) if ne > 0 else 0
        gk = np.empty(m, dtype=np.uint64)
        for i in range(m):
            k = np.uint64(0x2545F4914F6CDD1D)
            for q in range(ne):
                k = (k ^ tok_keys[ids[a + i + q]]) * np.uint64(0x100000001B3)
                k ^= np.uint64(q + 1)
            gk[i] = k
        acc = np.zeros(d, dtype=np.float64)
        for i in range(m):
            s = gk[i]
            j = 0
            while j < d:
                s, g1, g2 = _gauss_pair(s)
                acc[j] += g1
                if j + 1 < d:
                    acc[j + 1] += g2
                j += 2
        # ||x||^2 = sum of squared n-gram counts
        srt = np.sort(gk)
        ss = 0.0
        i = 0
        while i < m:
            c = 1
            while i + c < m and srt[i + c] == srt[i]:
                c += 1
            ss += c * c
            i += c
        norm = np.sqrt(ss) if ss > 0 else 1.0
        scale = np.sqrt(2.0 / d)
        for j in range(d):
            out[r, j] = scale * np.cos(acc[j] / norm / sigma + phase[j])
    return out


# ---------------------------------------------------------------- encoders

class _Vocab:
    """Token string -> dense id, with CSR packing of comma-joined chains."""

    def __init__(self):
        self.ids: dict[str, int] = {}

    def pack(self, chains: list[str]) -> tuple[np.ndarray, np.ndarray]:
        offsets = np.zeros(len(chains) + 1, dtype=np.int64)
        flat: list[int] = []
        get = self.ids.setdefault
        for i, ch in enumerate(chains):
            for t in ch.split(","):
                flat.append(get(t, len(self.ids)))
            offsets[i + 1] = len(flat)
        return offsets, np.asarray(flat, dtype=np.int64)

    def tokens(self) -> list[str]:
        out = [""] * len(self.ids)
        for t, i in self.ids.items():
            out[i] = t
        return out


class HDCEncoder:
    """Field-structured MAP encoder.  Same seed -> same vectors."""

    def __init__(self, seed: int = 0, d: int = D_DEFAULT, n: int = NGRAM):
        self.seed, self.d, self.n = seed, d, n
        roles = np.array([key64(seed, "role", r) for r in ("f", "p", "t")],
                         dtype=np.uint64)
        self.roles = _bipolar_rows(roles, d)
        self.tie = _bipolar_rows(np.array([key64(seed, "tie")],
                                          dtype=np.uint64), d)[0]

    def field_memory(self, tokens: list[str]):
        """Role-bound item vectors per distinct field value, and for each
        token the rows of its flags / port / tempo values."""
        rows: dict[tuple[int, str], int] = {}
        idx = np.empty((len(tokens), 3), dtype=np.int64)
        for t, tok in enumerate(tokens):
            for r, val in enumerate(split_token(tok)):
                idx[t, r] = rows.setdefault((r, val), len(rows))
        keys = np.empty(len(rows), dtype=np.uint64)
        role = np.empty(len(rows), dtype=np.int64)
        for (r, val), i in rows.items():
            keys[i] = key64(self.seed, "fpt"[r], val)
            role[i] = r
        fv = _bipolar_rows(keys, self.d) * self.roles[role]     # bind role
        return fv, idx[:, 0].copy(), idx[:, 1].copy(), idx[:, 2].copy()

    def encode(self, chains: list[str]) -> np.ndarray:
        """int8 +/-1 matrix, one row per chain."""
        voc = _Vocab()
        offsets, ids = voc.pack(chains)
        fv, tf, tp, tm = self.field_memory(voc.tokens())
        return _encode(fv, tf, tp, tm, offsets, ids, self.tie, self.n)


def rff_encode(chains: list[str], seed: int = 0, d: int = D_DEFAULT,
               n: int = NGRAM, sigma: float = 1.0) -> np.ndarray:
    """Classical twin of HDCEncoder.encode (whole-token n-grams, RFF)."""
    voc = _Vocab()
    offsets, ids = voc.pack(chains)
    tok_keys = np.array([key64(seed, "tok", t) for t in voc.tokens()],
                        dtype=np.uint64)
    phase = np.random.default_rng(key64(seed, "phase") % (2**63)).uniform(
        0.0, 2.0 * np.pi, d)
    return _rff(tok_keys, offsets, ids, n, phase, sigma)


# ---------------------------------------------------------------- similarity

def unit(x: np.ndarray) -> np.ndarray:
    """float32 rows scaled to unit L2 norm (cosine via plain dot).

    int8 bipolar rows all have norm sqrt(D), so they are scaled exactly."""
    if x.dtype == np.int8:
        return x.astype(np.float32) * np.float32(1.0 / np.sqrt(x.shape[1]))
    x = np.asarray(x, dtype=np.float32)
    nrm = np.linalg.norm(x, axis=1, keepdims=True)
    return x / np.maximum(nrm, 1e-12)


def max_sim(q: np.ndarray, mem: np.ndarray, idx: np.ndarray | None = None,
            chunk: int = 2048, mem_chunk: int = 16384,
            q_idx: np.ndarray | None = None
            ) -> tuple[np.ndarray, np.ndarray]:
    """Best cosine of each row of ``q`` against the rows ``mem[idx]`` (all
    rows when ``idx`` is None), and the position in ``idx`` of that row.

    Exact 1-NN by chunked matrix product.  Rows may be int8 bipolar or
    float; each memory chunk is converted to unit float32 on the fly, so
    peak memory is one chunk, not a float copy of the whole memory.  With
    ``q_idx`` the queries are the rows ``q[q_idx]``, read one chunk at a
    time (``q`` can then be a memmap)."""
    n_q = len(q) if q_idx is None else len(q_idx)
    best = np.full(n_q, -np.inf, dtype=np.float32)
    arg = np.full(n_q, -1, dtype=np.int64)
    n_mem = len(mem) if idx is None else len(idx)
    if n_mem == 0:
        return np.full(n_q, -1.0, dtype=np.float32), arg
    if np.dtype(q.dtype) == np.int8 and np.dtype(mem.dtype) == np.int8:
        # bipolar rows: cosine = 1 - 2 * Hamming / D on packed bits, the
        # same value as the float32 product at ~1/15 of the CPU
        # (bench/efficiency.py, round 2 correction D15)
        d = mem.shape[1]
        for j in range(0, n_mem, mem_chunk):
            rows = slice(j, j + mem_chunk) if idx is None else idx[j:j + mem_chunk]
            mp = pack_bits(np.asarray(mem[rows]))
            for i in range(0, n_q, chunk):
                qc = q[i:i + chunk] if q_idx is None else q[q_idx[i:i + chunk]]
                h, a = _hamming_best(pack_bits(np.asarray(qc)), mp)
                b = (1.0 - 2.0 * h / d).astype(np.float32)
                better = b > best[i:i + chunk]
                best[i:i + chunk][better] = b[better]
                arg[i:i + chunk][better] = a[better] + j
        return best, arg
    for j in range(0, n_mem, mem_chunk):
        rows = slice(j, j + mem_chunk) if idx is None else idx[j:j + mem_chunk]
        m = mem[rows]
        if m.dtype == np.int8:
            m = unit(m)
        else:                          # unit() in place: no second chunk copy
            m = np.array(m, dtype=np.float32, copy=True)
            m /= np.maximum(np.linalg.norm(m, axis=1, keepdims=True), 1e-12)
        for i in range(0, n_q, chunk):
            # unit rows per query chunk: no float copy of the whole query
            qc = q[i:i + chunk] if q_idx is None else q[q_idx[i:i + chunk]]
            sim = unit(np.asarray(qc)) @ m.T
            a = sim.argmax(axis=1)
            b = sim[np.arange(len(sim)), a]
            better = b > best[i:i + chunk]
            best[i:i + chunk][better] = b[better]
            arg[i:i + chunk][better] = a[better] + j
    return best, arg


def pack_bits(v: np.ndarray) -> np.ndarray:
    """int8 +/-1 rows -> uint64 words (bit = 1 for +1), padded to 64 bits."""
    bits = np.packbits(v > 0, axis=1)
    pad = (-bits.shape[1]) % 8
    if pad:
        bits = np.pad(bits, ((0, 0), (0, pad)))
    return np.ascontiguousarray(bits).view(np.uint64)


@njit(cache=True, parallel=True)
def _hamming_best(q, m):
    """Lowest Hamming distance of each packed row of q against m, and the
    first row of m with it (the float path's argmax order)."""
    nq, nw = q.shape
    best = np.empty(nq, dtype=np.int64)
    arg = np.zeros(nq, dtype=np.int64)
    c1 = np.uint64(0x5555555555555555)
    c2 = np.uint64(0x3333333333333333)
    c4 = np.uint64(0x0F0F0F0F0F0F0F0F)
    h01 = np.uint64(0x0101010101010101)
    for i in prange(nq):
        bi = 1 << 62
        ai = 0
        for j in range(m.shape[0]):
            dd = 0
            for w in range(nw):
                x = q[i, w] ^ m[j, w]
                x = x - ((x >> np.uint64(1)) & c1)
                x = (x & c2) + ((x >> np.uint64(2)) & c2)
                x = (x + (x >> np.uint64(4))) & c4
                dd += np.int64((x * h01) >> np.uint64(56))
            if dd < bi:
                bi = dd
                ai = j
        best[i] = bi
        arg[i] = ai
    return best, arg


def floor_noise(sim: np.ndarray, d: int, z: float = 5.0) -> np.ndarray:
    """Cosine with the random-vector noise floor removed.

    Unrelated D-dim bipolar vectors have cosine ~ N(0, 1/sqrt(D)), so the
    best match of a truly new chain against ~1e5 memory rows is the maximum
    of 1e5 noise draws (~4.3 sigma) and changes with the encoder seed.
    Similarity at or below ``z`` sigma is set to 0 and the rest is rescaled
    to 0..1, so new chains tie (and the caller's fixed tie-break orders
    them) instead of being ranked by seed noise.
    """
    tau = z / np.sqrt(d)
    return np.clip((np.asarray(sim, dtype=np.float64) - tau) / (1.0 - tau),
                   0.0, 1.0)


def prototypes(x: np.ndarray, w: np.ndarray, k: int, seed: int,
               iters: int = 10, binarize: bool = True) -> np.ndarray:
    """``k`` weighted spherical k-means prototypes of unit rows ``x``.

    Centroids are re-binarized each step (sign of the weighted bundle), so a
    prototype is itself a valid hypervector; ``binarize=False`` keeps the
    plain weighted mean direction (the classical twin).  Returns unit rows."""
    if len(x) <= k:
        return x.copy()
    rng = np.random.default_rng(seed)
    p = np.asarray(w, dtype=np.float64)
    c = x[rng.choice(len(x), k, replace=False, p=p / p.sum())]
    for _ in range(iters):
        _, a = max_sim(x, c)
        # weighted bundle per cluster as one-hot^T @ (w * x) (np.add.at is
        # ~100x slower here)
        onehot = np.zeros((len(x), k), dtype=np.float32)
        onehot[np.arange(len(x)), a] = w
        nc = onehot.T @ x
        empty = ~np.any(nc, axis=1)
        nc[empty] = c[empty]
        c = unit(np.sign(nc) + (nc == 0) * 1e-3 if binarize else nc)
    return c

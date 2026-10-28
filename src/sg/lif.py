"""
sg.lif — event-driven LIF / ALIF neuron banks for per-source packet timing.

Neuromorphic plan Phase 3 (docs/ARCHITECTURE.md §9.1).  Each packet of a
source is one input spike to a bank of leaky integrate-and-fire neurons
with time constants ``taus``.  Between spikes the membrane decays exactly
(event-driven, no time step):

    v_k(t_i^-) = v_k(t_{i-1}^+) * exp(-(t_i - t_{i-1}) / tau_k)
    v_k(t_i^+) = v_k(t_i^-) + 1

The pre-spike potential v_k(t_i^-) is the neuron's view of the recent
rate: about rate * tau_k when tau_k is much larger than the inter-arrival
time, and near exp(-IAT / tau_k) when it is about the same.

Two readouts per source (both from the same bank):

  change      ALIF rate shift.  Each neuron in the change band keeps two
              traces of log v_k(t_i^-): a fast mean m_f (the last ~``n_fast``
              spikes) and an adaptive threshold, the mean m_s and variance
              q_s of every spike since the last reset.  The score is the
              largest |m_f - m_s| / sqrt(q_s + s0^2) after ``warm`` spikes.
              A source that keeps its own rhythm stays near its threshold,
              however bursty it is; a sustained change of rate moves m_f
              away from m_s for many spikes.
  regularity  log(mean / std) of v_k(t_i^-) for the neurons in the band,
              after ``warm`` spikes (the rise from v = 0 is not counted).
              A metronome gives the same pre-spike potential at every
              spike (std near 0); a Poisson source gives a relative
              spread near 1 at tau ~ IAT.

The bands are the neurons with tau_k in ``band`` (regularity, default
0.5 .. 2) and ``change_band`` (default 1 .. 16) x the source's median
inter-arrival time; an empty band falls back to the neuron nearest the
median.  ``band = change_band = (0, inf)`` select every neuron (the
untrained copy).  ``adapt=False`` freezes the threshold at m_s = 0,
q_s = 0 (the untrained copy: z = |m_f| / s0).

State resets at each sensor-mask segment change (rule 2 of §9.3): the
caller passes a segment id for each packet.

``hawkes_ks`` is the classical twin: the same exponential kernel as a
self-exciting (Hawkes) intensity, fit per source by EM over a beta grid,
scored by the time-rescaling Kolmogorov-Smirnov statistic sqrt(n) * D.
"""
from __future__ import annotations

import math

import numpy as np
from numba import njit

TAUS = np.geomspace(1e-3, 86400.0, 24)   # 1 ms .. 1 day
N_FAST = 32         # fast trace memory (spikes)
WARM = 16           # spikes after a reset with no change score
S0 = 0.25           # threshold variance floor (log units)
BAND = (0.5, 2.0)   # regularity band, x median IAT
CHANGE_BAND = (1.0, 16.0)   # change band, x median IAT
EPS = 1e-12
TAIL_Q = 0.9        # calibrate(): start of the exponential tail


@njit(cache=True)
def _band(taus, med, lo, hi):
    K = len(taus)
    out = np.zeros(K, dtype=np.bool_)
    for k in range(K):
        out[k] = taus[k] >= lo * med and taus[k] <= hi * med
    if not out.any():
        best, bk = 1e300, 0
        for k in range(K):
            dd = abs(math.log(taus[k]) - math.log(max(med, 1e-6)))
            if dd < best:
                best, bk = dd, k
        out[bk] = True
    return out


@njit(cache=True)
def _bank(t, seg, starts, med, taus, band_lo, band_hi, ch_lo, ch_hi, adapt,
          n_fast, warm, s0):
    S = len(starts) - 1
    K = len(taus)
    change = np.zeros(S)
    reg = np.full(S, -np.inf)
    v = np.zeros(K)
    mf = np.zeros(K)
    ms = np.zeros(K)
    qs = np.zeros(K)
    sp = np.zeros(K)
    sp2 = np.zeros(K)
    nreg = np.zeros(K)
    for s in range(S):
        a, b = starts[s], starts[s + 1]
        rb = _band(taus, med[s], band_lo, band_hi)
        cb = _band(taus, med[s], ch_lo, ch_hi)
        for k in range(K):
            sp[k] = 0.0
            sp2[k] = 0.0
            nreg[k] = 0.0
        best = 0.0
        n = 0
        last_t = 0.0
        last_seg = -1
        for i in range(a, b):
            if seg[i] != last_seg:      # reset at a mask end
                for k in range(K):
                    v[k] = 0.0
                    mf[k] = 0.0
                    ms[k] = 0.0
                    qs[k] = 0.0
                n = 0
                last_seg = seg[i]
                last_t = t[i]
            dt = t[i] - last_t
            last_t = t[i]
            for k in range(K):
                v[k] *= math.exp(-dt / taus[k])
            if n >= 1:
                for k in range(K):
                    if rb[k] and n >= warm:     # skip the rise from v = 0
                        sp[k] += v[k]
                        sp2[k] += v[k] * v[k]
                        nreg[k] += 1.0
                    if not cb[k]:
                        continue
                    lp = math.log(v[k] + EPS)
                    if n == 1:
                        mf[k] = lp
                        if adapt:
                            ms[k] = lp
                    else:
                        mf[k] += max(1.0 / n, 1.0 / n_fast) * (lp - mf[k])
                        if adapt:
                            d = lp - ms[k]
                            ms[k] += d / n
                            qs[k] += (d * (lp - ms[k]) - qs[k]) / n
                    if n >= warm:
                        z = abs(mf[k] - ms[k]) / math.sqrt(qs[k] + s0 * s0)
                        if z > best:
                            best = z
            for k in range(K):
                v[k] += 1.0
            n += 1
        change[s] = best
        for k in range(K):
            if rb[k] and nreg[k] >= 4:
                mu = sp[k] / nreg[k]
                var = max(sp2[k] / nreg[k] - mu * mu, 0.0)
                r = math.log((mu + EPS) / (math.sqrt(var) + 1e-9 * (mu + EPS)))
                if r > reg[s]:
                    reg[s] = r
    return change, reg


def bank_scores(t: np.ndarray, seg: np.ndarray, starts: np.ndarray,
                med: np.ndarray, taus: np.ndarray = TAUS,
                band: tuple[float, float] = BAND,
                change_band: tuple[float, float] = CHANGE_BAND,
                adapt: bool = True, n_fast: int = N_FAST, warm: int = WARM,
                s0: float = S0) -> tuple[np.ndarray, np.ndarray]:
    """(change, regularity) for each source.  ``t`` is float64 seconds,
    sorted inside each source; source s owns t[starts[s]:starts[s+1]]."""
    return _bank(np.ascontiguousarray(t, dtype=np.float64),
                 np.ascontiguousarray(seg, dtype=np.int64),
                 np.ascontiguousarray(starts, dtype=np.int64),
                 np.ascontiguousarray(med, dtype=np.float64),
                 np.ascontiguousarray(taus, dtype=np.float64),
                 float(band[0]), float(band[1]), float(change_band[0]),
                 float(change_band[1]), bool(adapt), float(n_fast),
                 int(warm), float(s0))


def median_iat(t: np.ndarray, seg: np.ndarray, starts: np.ndarray) -> np.ndarray:
    """Median inter-arrival time of each source inside its mask segments
    (ties at 0 s are kept; the floor is 1 ms)."""
    d = np.diff(t, prepend=t[:1])
    same = np.zeros(len(t), dtype=bool)
    same[1:] = seg[1:] == seg[:-1]
    first = np.zeros(len(t), dtype=bool)
    first[starts[:-1]] = True
    keep = same & ~first
    out = np.full(len(starts) - 1, np.nan)
    owner = np.repeat(np.arange(len(starts) - 1), np.diff(starts))
    if keep.any():
        o, dk = owner[keep], d[keep]
        order = np.lexsort((dk, o))
        o, dk = o[order], dk[order]
        bnd = np.searchsorted(o, np.arange(len(starts)))
        for s in range(len(starts) - 1):
            x = dk[bnd[s]:bnd[s + 1]]
            if len(x):
                out[s] = x[len(x) // 2]
    return np.maximum(np.nan_to_num(out, nan=1.0), 1e-3)


# ---------------------------------------------------------------- Hawkes twin

@njit(cache=True)
def _hawkes_fit_ks(t, seg, a, b, betas, iters):
    """EM fit of mu, alpha (branching ratio) for each beta; the best
    log-likelihood wins.  Returns (sqrt(n) * KS D, mu, alpha, beta)."""
    # segment spans: each segment is its own observation window
    n = b - a
    best_ll, best = -1e300, (0.0, 0.0, 1.0)
    lam = np.empty(n)
    for bi in range(len(betas)):
        beta = betas[bi]
        T, comp = 0.0, 0.0           # window length, sum of (1 - e^{-beta(T_end - t_j)})
        i = a
        while i < b:                  # one pass for T and the compensator term
            j = i
            while j + 1 < b and seg[j + 1] == seg[i]:
                j += 1
            T += t[j] - t[i]
            for x in range(i, j + 1):
                comp += 1.0 - math.exp(-beta * (t[j] - t[x]))
            i = j + 1
        if T <= 0.0:
            continue
        mu, al = 0.5 * n / T, 0.5
        for _ in range(iters):
            # lambda_i = mu + al * beta * A_i, A_i = sum_{j<i} e^{-beta(t_i - t_j)}
            A, last_seg, last_t = 0.0, -1, 0.0
            s_bg, s_tr = 0.0, 0.0
            for x in range(a, b):
                if seg[x] != last_seg:
                    A, last_seg, last_t = 0.0, seg[x], t[x]
                else:
                    A = (A + 1.0) * math.exp(-beta * (t[x] - last_t))
                    last_t = t[x]
                lam[x - a] = mu + al * beta * A
                s_bg += mu / lam[x - a]
                s_tr += 1.0 - mu / lam[x - a]
            mu = max(s_bg / T, 1e-12)
            al = min(s_tr / max(comp, 1e-12), 0.999)
        ll = 0.0
        for x in range(n):
            ll += math.log(lam[x])
        ll -= mu * T + al * comp
        if ll > best_ll:
            best_ll, best = ll, (mu, al, beta)
    mu, al, beta = best
    # time-rescaling: Lambda between successive spikes of a segment
    u = np.empty(n)
    m = 0
    A, last_seg, last_t = 0.0, -1, 0.0
    for x in range(a, b):
        if seg[x] != last_seg:
            A, last_seg, last_t = 0.0, seg[x], t[x]
            continue
        dt = t[x] - last_t
        Ap = A + 1.0                   # sum over spikes <= previous, at prev time
        lam_int = mu * dt + al * Ap * (1.0 - math.exp(-beta * dt))
        u[m] = 1.0 - math.exp(-lam_int)
        m += 1
        A = Ap * math.exp(-beta * dt)
        last_t = t[x]
    if m < 2:
        return 0.0, mu, al, beta
    uu = np.sort(u[:m])
    d = 0.0
    for x in range(m):
        d = max(d, abs((x + 1) / m - uu[x]), abs(uu[x] - x / m))
    return math.sqrt(m) * d, mu, al, beta


@njit(cache=True)
def _hawkes_all(t, seg, starts, med, iters):
    S = len(starts) - 1
    ks = np.zeros(S)
    br = np.zeros(S)
    for s in range(S):
        base = 1.0 / max(med[s], 1e-3)
        betas = np.empty(8)
        for k in range(8):
            betas[k] = base * 10.0 ** (-1.5 + 0.5 * k)   # 0.03 .. 100 x rate
        ks[s], _, br[s], _ = _hawkes_fit_ks(t, seg, starts[s], starts[s + 1],
                                            betas, iters)
    return ks, br


def hawkes_scores(t: np.ndarray, seg: np.ndarray, starts: np.ndarray,
                  med: np.ndarray, iters: int = 20
                  ) -> tuple[np.ndarray, np.ndarray]:
    """(sqrt(n) * KS D, branching ratio) of the exponential Hawkes fit of
    each source."""
    return _hawkes_all(np.ascontiguousarray(t, dtype=np.float64),
                       np.ascontiguousarray(seg, dtype=np.int64),
                       np.ascontiguousarray(starts, dtype=np.int64),
                       np.ascontiguousarray(med, dtype=np.float64), int(iters))


# ---------------------------------------------------------------- calibration

def calibrate(score: np.ndarray, logn: np.ndarray, ref: np.ndarray,
           ref_logn: np.ndarray, n_bins: int = 10) -> np.ndarray:
    """-log10 of the exceedance rate of each score among the reference
    scores in the same log packet-count bin.  Above the bin's TAIL_Q
    quantile u the rate is the peaks-over-threshold exponential tail
    (1 - TAIL_Q) * exp(-(s - u) / mean excess), so scores above every
    reference score do not tie at one value."""
    edges = np.quantile(ref_logn, np.linspace(0, 1, n_bins + 1)[1:-1]) \
        if len(ref_logn) else np.array([])
    b, rb = np.searchsorted(edges, logn), np.searchsorted(edges, ref_logn)
    out = np.zeros(len(score))
    for k in range(n_bins):
        sel, rs = b == k, np.sort(ref[rb == k])
        if not sel.any() or not len(rs):
            continue
        sc = score[sel]
        ge = len(rs) - np.searchsorted(rs, sc, side="left")
        p = (1 + ge) / (1 + len(rs))
        u = np.quantile(rs, TAIL_Q)
        exc = rs[rs > u] - u
        if len(exc) >= 5 and exc.mean() > 0:
            hi = sc > u
            p[hi] = (1 - TAIL_Q) * np.exp(-(sc[hi] - u) / exc.mean())
        out[sel] = np.maximum(-np.log10(np.maximum(p, 1e-300)), 0.0)
    return out

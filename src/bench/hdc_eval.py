#!/usr/bin/env python3
"""
bench/hdc_eval — Phase 1 exit gate: HDC choreography novelty vs its baselines.

Neuromorphic plan Phase 1 (docs/ARCHITECTURE.md §9.1).  Scores every source
on the injected day D of one ``adversarysim --inject`` set, with the same
population, truth and recall@k arithmetic as ``bench/baselines.py``:

  hdc_novelty    1 - best cosine of the source's D sessions against every
                 distinct fit-window session (exact 1-NN, sg.hdc encoder;
                 cosine below the noise floor counts as 0, hdc.floor_noise)
  hdc_variant    best cosine for sessions whose exact chain was NOT seen in
                 the fit window ("a known choreography, changed")
  hdc_proto      1 - best cosine against k sub-prototypes per fit day
  hdc_drift      fast vs slow actor prototype divergence over the source's
                 own session sequence (sources with >= 3 sessions)
  hdc_align      round-2 primary: Y = the fit source-day whose session
                 bundle is nearest (cosine B) to the source's D bundle;
                 score = B**p x the worst D-session deviation from Y's
                 sessions ("a known actor, with a changed choreography")
  string_rarity  -log(1 + fit-window count of the exact chain)
                 (chainfp's tier logic as a continuous score)
  rff_novelty /  the same scores from the classical twin: whole-token
  rff_variant /  n-grams, random Fourier features (sg.hdc.rff_encode);
  rff_align /    rff_proto uses plain weighted spherical k-means (no sign
  rff_proto /    step) and neither rff score has a noise floor
  rff_drift
  str_align      hdc_align on exact chains (sparse bags, 0/1 deviation)

Sessions come from ``chainfp._window_sql`` (adaptive window, timed chains),
over the ``--fit-days`` recorded days before D plus D, minus the sensormask.
A source's score is the max over its sessions on D; sources with no
2-packet session score 0.

Gate (§9.1): an hdc_* score beats string_rarity and rff_* on chain_mutation,
and its top-k is stable across encoder seeds.  Stability = mean pairwise
Jaccard of the top-k source sets over ``--seeds``.

Output: output/reports/hdc_eval/hdc_eval_<NAME>.{parquet,md}
        output/reports/hdc_eval/hdc_stability_<NAME>.parquet
``--summary NAME [NAME ...]`` pools saved sets (with their baselines_<NAME>
rows) into hdc_eval_summary.{parquet,md}.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import itertools
import shutil
import sys
import tempfile
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import scipy.sparse as sp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import hdc, lib
import chainfp
from bench import baselines as bl

STABILITY_SCHEMA = pa.schema([
    ("eval_name", pa.string()),
    ("detector",  pa.string()),
    ("k",         pa.uint32()),
    ("n_seeds",   pa.uint32()),
    ("jaccard",   pa.float64()),
])

SUMMARY_SCHEMA = pa.schema([
    ("detector",   pa.string()),
    ("archetype",  pa.string()),
    ("is_control", pa.bool_()),
    ("k",          pa.uint32()),
    ("n_sets",     pa.uint32()),
    ("n_truth",    pa.uint32()),
    ("hits",       pa.uint32()),
    ("recall",     pa.float64()),
    ("chance",     pa.float64()),
])

HDC_DETECTORS = ("hdc_novelty", "hdc_variant", "hdc_proto", "hdc_drift",
                 "hdc_align")
DETECTORS = HDC_DETECTORS + ("string_rarity", "str_align", "rff_novelty",
                             "rff_variant", "rff_align", "rff_proto",
                             "rff_drift")
OUT = lib.REPORTS / "hdc_eval"


# ---------------------------------------------------------------- data
#
# Nothing here holds the full window in memory at one time:
#   - sessions are made per hash(src_ip) bucket and written to Parquet; the
#     scorer gets only integer ids (source, chain, day) for each session;
#   - the vectors of each family and seed go to a disk-backed memmap, which
#     the 1-NN search, the bundles and the drift read in chunks.
# Each chunked step does the same arithmetic per row as the whole-matrix
# form, so the scores do not change.

PKTS_PER_BUCKET = 4_000_000        # DuckDB window functions cannot spill
ENC_CHUNK = 16384                  # chains per encoder call
BUNDLE_NNZ = 1 << 15               # (source-day, chain) pairs per bundle chunk
XY_CELLS = 1 << 26                 # chain-pair cells per deviation block


def _auto_buckets(con, days: list[_dt.date]) -> int:
    n = con.execute(f"""
        SELECT count(*) FROM packets
        WHERE {bl._days_pred(days)} AND {lib.mask_predicate('ts')}
    """).fetchone()[0]
    return max(1, -(-n // PKTS_PER_BUCKET))


def _sessions(con, days: list[_dt.date], max_tokens: int, buckets: int,
              tmp: Path) -> dict:
    """Sessions over ``days`` as integer arrays.

    Rows are ordered by (src_ip, first_ts, tchain).  ``iid`` and ``cid``
    index ``ips`` and ``chains`` (both sorted), and ``di`` indexes ``days``
    by the UTC date of the session start (-1 when that date is not in
    ``days``).  Every step of chainfp's window SQL is per source, so one
    query per hash(src_ip) bucket gives the same sessions as one query for
    all sources."""
    base = f"{bl._days_pred(days)} AND {lib.mask_predicate('ts')}"
    for b in range(buckets):
        where = base + (f" AND hash(src_ip) % {buckets} = {b}"
                        if buckets > 1 else "")
        sql = chainfp._window_sql(where, None, 2, max_tokens)
        con.execute(f"""
            COPY (SELECT src_ip, tchain, first_ts FROM ({sql})
                  WHERE tchain IS NOT NULL)
            TO '{tmp / f"sess_{b:03d}.parquet"}' (FORMAT parquet)
        """)
    src = f"read_parquet('{tmp}/sess_*.parquet')"
    con.execute(f"""
        CREATE TEMP TABLE hc AS
        SELECT tchain, (row_number() OVER (ORDER BY tchain) - 1)::INT AS cid
        FROM (SELECT DISTINCT tchain FROM {src})
    """)
    con.execute(f"""
        CREATE TEMP TABLE hi AS
        SELECT src_ip, (row_number() OVER (ORDER BY src_ip) - 1)::INT AS iid
        FROM (SELECT DISTINCT src_ip FROM {src})
    """)
    chains = [r[0] for r in con.execute(
        "SELECT tchain FROM hc ORDER BY cid").fetchall()]
    ips = [r[0] for r in con.execute(
        "SELECT src_ip FROM hi ORDER BY iid").fetchall()]
    # the encoders and the tie-breaks expect Python string order
    if chains != sorted(chains) or ips != sorted(ips):
        raise SystemExit("[hdc_eval] DuckDB string order is not Python order")
    dv = ", ".join(f"(DATE '{d}', {i})" for i, d in enumerate(days))
    t = con.execute(f"""
        SELECT hc.cid, hi.iid, coalesce(dd.di, -1)::TINYINT AS di
        FROM {src} s
        JOIN hc USING (tchain)
        JOIN hi USING (src_ip)
        LEFT JOIN (VALUES {dv}) dd(day, di)
               ON dd.day = CAST(timezone('UTC', s.first_ts) AS DATE)
        ORDER BY s.src_ip, s.first_ts, s.tchain
    """).to_arrow_table()
    return {"cid": t["cid"].to_numpy(), "iid": t["iid"].to_numpy(),
            "di": t["di"].to_numpy(), "chains": chains, "ips": ips}


def _population(con, day: _dt.date) -> list[str]:
    """Same source set as baselines._source_features on D."""
    ips = [r[0] for r in con.execute(f"""
        SELECT DISTINCT src_ip FROM packets
        WHERE dt = DATE '{day}' AND {lib.mask_predicate('ts')}
    """).fetchall()]
    return sorted(ip for ip in ips if lib.is_real_external_ip(ip))


def _store(fam: str, chains: list[str], seed: int, dim: int, path: Path,
           device: str = "cpu"):
    """Vectors of all chains in a read-only memmap: int8 bipolar rows (hdc)
    or unit float32 rows (rff).  Rows are encoded in chunks; each row
    depends only on its own chain and the seed.  device="gpu" encodes hdc
    rows with sg.hdc_gpu (bit-exact)."""
    dtype = np.int8 if fam == "hdc" else np.float32
    mm = np.lib.format.open_memmap(path, mode="w+", dtype=dtype,
                                   shape=(len(chains), dim))
    enc = hdc.HDCEncoder(seed, dim) if fam == "hdc" else None
    for a in range(0, len(chains), ENC_CHUNK):
        part = chains[a:a + ENC_CHUNK]
        if enc is not None and device == "gpu":
            from sg import hdc_gpu
            mm[a:a + len(part)] = hdc_gpu.encode(enc, part)
        elif enc is not None:
            mm[a:a + len(part)] = enc.encode(part)
        else:
            v = hdc.rff_encode(part, seed, dim)
            v /= np.maximum(np.linalg.norm(v, axis=1, keepdims=True), 1e-12)
            mm[a:a + len(part)] = v
    mm.flush()
    del mm
    return np.load(path, mmap_mode="r")


# ---------------------------------------------------------------- scoring

def _per_source(pop_of: np.ndarray, n_pop: int, sess_iid: np.ndarray,
                vals) -> np.ndarray:
    """Max session value per population source (0 when it has none).

    ``pop_of`` maps a source id to its population index (-1 = not scored)."""
    p = pop_of[sess_iid]
    keep = p >= 0
    out = np.full(n_pop, -np.inf)
    np.maximum.at(out, p[keep], np.asarray(vals, dtype=np.float64)[keep])
    out[np.isneginf(out)] = 0.0
    return out


def _drift(vecs, sid: np.ndarray, iid: np.ndarray, is_d: np.ndarray,
           alpha_fast: float, alpha_slow: float, min_sess: int) -> np.ndarray:
    """Per session: 1 - cos(fast, slow) after the session is absorbed.

    Sessions are ordered by (source, time) and ``vecs[sid[i]]`` is session
    i's vector.  The state carries over from the fit days, but only D
    sessions get a value, so sources with no D session are skipped.
    """
    out = np.zeros(len(sid))
    cut = np.flatnonzero(np.diff(iid)) + 1
    for start, end in zip(np.r_[0, cut], np.r_[cut, len(iid)]):
        if end - start >= min_sess and is_d[start:end].any():
            # bipolar rows share one norm, so cosine needs no rescaling
            fast = vecs[sid[start]].astype(np.float64)
            slow = fast.copy()
            for i in range(start + 1, end):
                v = vecs[sid[i]].astype(np.float64)
                fast = (1 - alpha_fast) * fast + alpha_fast * v
                slow = (1 - alpha_slow) * slow + alpha_slow * v
                if is_d[i] and i - start + 1 >= min_sess:
                    c = fast @ slow / max(np.linalg.norm(fast)
                                          * np.linalg.norm(slow), 1e-12)
                    out[i] = 1.0 - c
    return out


def _src_days(sid: np.ndarray, iid: np.ndarray, di: np.ndarray,
              sel: np.ndarray, n_chains: int, weight: str):
    """CSR (source-day x chain) matrix of the sessions in ``sel``, rows in
    order of first appearance, and the source id of each row."""
    key = iid[sel].astype(np.int64) * 256 + (di[sel].astype(np.int64) + 1)
    _, first, inv = np.unique(key, return_index=True, return_inverse=True)
    rank = np.empty(len(first), dtype=np.int64)
    rank[np.argsort(first, kind="stable")] = np.arange(len(first))
    m = sp.csr_matrix((np.ones(len(inv), np.float32), (rank[inv], sid[sel])),
                      shape=(len(first), n_chains))
    m.sum_duplicates()
    if weight == "distinct":
        m.data[:] = 1.0
    return m, iid[sel][np.sort(first)]


def _rownorm(x):
    if sp.issparse(x):
        n = np.sqrt(np.asarray(x.multiply(x).sum(axis=1)).ravel())
        return sp.diags(1.0 / np.maximum(n, 1e-12)) @ x
    return x / np.maximum(np.linalg.norm(x, axis=1, keepdims=True), 1e-12)


def _bundles(m, vecs, out) -> None:
    """``out`` = unit rows of ``m @ vecs``, in row chunks.

    scipy makes a float32 copy of the whole dense operand (13 GB for an
    int8 HDC matrix of 4e5 chains), so each chunk multiplies only the
    chains that its rows use.  The product per row is the same sum."""
    a, n = 0, m.shape[0]
    while a < n:
        b = a + 1
        while b < n and m.indptr[b + 1] - m.indptr[a] <= BUNDLE_NNZ:
            b += 1
        sub = m[a:b]
        cols = np.unique(sub.indices)
        sub = sp.csr_matrix((sub.data, np.searchsorted(cols, sub.indices),
                             sub.indptr), shape=(b - a, len(cols)))
        out[a:b] = _rownorm(sub @ np.asarray(vecs[cols]))
        a = b


def _worst_dev(vecs, xc: np.ndarray, yc: np.ndarray) -> float:
    """min over x of max over y of the cosine (unscaled), in blocks."""
    if len(xc) * len(yc) <= XY_CELLS:
        return float((vecs[xc].astype(np.float32)
                      @ vecs[yc].astype(np.float32).T).max(axis=1).min())
    yb = max(1, XY_CELLS // max(1, min(len(xc), 4096)))
    best = []
    for i in range(0, len(xc), 4096):
        x = vecs[xc[i:i + 4096]].astype(np.float32)
        mx = np.full(len(x), -np.inf, dtype=np.float32)
        for j in range(0, len(yc), yb):
            mx = np.maximum(mx, (x @ vecs[yc[j:j + yb]].astype(
                np.float32).T).max(axis=1))
        best.append(mx.min())
    return float(min(best))


def _align(vecs, dm, fm, power: float, scale: float = 1.0,
           tmp: Path | None = None, chunk: int = 512) -> np.ndarray:
    """Per D source-day: B**power * worst session deviation from Y.

    Y is the fit source-day with the highest bundle cosine B.  The deviation
    of one D chain is 1 - its best cosine against Y's chains, so an exact
    replay of Y scores 0 and an unrelated source has a low B.  ``vecs`` are
    chain vectors whose rows have length 1/sqrt(scale); None gives the
    exact-string twin (bags of chains, deviation 1 for a chain that Y does
    not have).  The fit bundles go to a memmap in ``tmp`` when it is given.
    """
    if vecs is None:
        q, mem = _rownorm(dm), _rownorm(fm)
    else:
        q = np.empty((dm.shape[0], vecs.shape[1]), dtype=np.float32)
        _bundles(dm, vecs, q)
        if tmp is None:
            mem = np.empty((fm.shape[0], vecs.shape[1]), dtype=np.float32)
        else:
            mem = np.lib.format.open_memmap(
                tmp / "fit_bundles.npy", mode="w+", dtype=np.float32,
                shape=(fm.shape[0], vecs.shape[1]))
        _bundles(fm, vecs, mem)
    out = np.zeros(dm.shape[0])
    for a in range(0, dm.shape[0], chunk):
        sim = q[a:a + chunk] @ mem.T
        sim = sim.toarray() if sp.issparse(sim) else np.asarray(sim)
        for r, (y, b) in enumerate(zip(sim.argmax(axis=1), sim.max(axis=1))):
            j = a + r
            xc = dm.indices[dm.indptr[j]:dm.indptr[j + 1]]
            yc = fm.indices[fm.indptr[y]:fm.indptr[y + 1]]
            if vecs is None:
                dev = 0.0 if np.isin(xc, yc).all() else 1.0
            else:
                dev = 1.0 - scale * _worst_dev(vecs, xc, yc)
            out[j] = max(b, 0.0) ** power * dev
    del mem
    return out


def score_set(s: dict, fit_days, ips, seeds, args, tmp: Path
              ) -> dict[int, dict]:
    """{seed: {detector: per-source score array}} from ``_sessions`` rows.

    ``s["di"]`` indexes fit_days + [D]; ``ips`` is the scored population."""
    n_fit = len(fit_days)
    di, sid, iid = s["di"], s["cid"].astype(np.int64), s["iid"]
    is_d = di == n_fit
    in_fit = (di >= 0) & (di < n_fit)
    n_chains = len(s["chains"])
    pos = {ip: i for i, ip in enumerate(s["ips"])}
    pop_of = np.full(len(s["ips"]), -1, dtype=np.int64)
    for j, ip in enumerate(ips):
        if ip in pos:
            pop_of[pos[ip]] = j

    def per(sess_iid, vals):
        return _per_source(pop_of, len(ips), sess_iid, vals)

    fit_count = np.bincount(sid[in_fit], minlength=n_chains)
    fit_ids = np.flatnonzero(fit_count)
    d_idx = np.flatnonzero(is_d)
    d_iid = iid[d_idx]
    # nearest-neighbour work is per distinct D chain, then mapped back
    d_uniq, d_inv = np.unique(sid[d_idx], return_inverse=True)
    unseen = fit_count[sid[d_idx]] == 0
    print(f"[hdc_eval] {len(sid):,} sessions, {n_chains:,} distinct "
          f"chains, {len(fit_ids):,} in fit memory, {len(d_idx):,} on D",
          file=sys.stderr)

    def want(det: str) -> bool:
        return not args.only or det in args.only

    device = getattr(args, "device", "cpu")

    rarity = per(d_iid, -np.log1p(fit_count[sid[d_idx]]))
    if any(want(f"{f}_align") for f in ("str", "hdc", "rff")):
        fm, _ = _src_days(sid, iid, di, in_fit, n_chains, args.align_weight)
        dm, dm_iid = _src_days(sid, iid, di, is_d, n_chains,
                               args.align_weight)
    if want("str_align"):
        str_align = per(dm_iid, _align(None, dm, fm, args.align_power))
    out: dict[int, dict] = {}
    for seed in seeds:
        sc: dict[str, np.ndarray] = {}
        if want("string_rarity"):
            sc["string_rarity"] = rarity
        if want("str_align"):
            sc["str_align"] = str_align
        for fam in ("hdc", "rff"):
            if not any(want(f"{fam}_{x}") for x in
                       ("novelty", "variant", "align", "proto", "drift")):
                continue
            path = tmp / f"{fam}_{seed}.npy"
            vecs = _store(fam, s["chains"], seed, args.dim, path, device)
            # the noise floor is a property of random bipolar vectors
            floor = ((lambda x: hdc.floor_noise(x, args.dim, args.noise_z))
                     if fam == "hdc" else (lambda x: x))
            if want(f"{fam}_novelty") or want(f"{fam}_variant"):
                nn, _ = hdc.max_sim(vecs, vecs, fit_ids, q_idx=d_uniq)
                nn = floor(nn[d_inv])
                sc[f"{fam}_novelty"] = per(d_iid, 1.0 - nn)
                sc[f"{fam}_variant"] = per(d_iid, np.where(unseen, nn, 0.0))
            if want(f"{fam}_align"):
                # bipolar int8 rows all have norm sqrt(D); RFF rows are unit
                sc[f"{fam}_align"] = per(dm_iid, _align(
                    vecs, dm, fm, args.align_power,
                    1.0 / args.dim if fam == "hdc" else 1.0, tmp))
            if want(f"{fam}_proto") and fam == "hdc" and device == "gpu":
                from sg import hdc_gpu
                protos = []
                for k in range(n_fit):
                    m = np.bincount(sid[di == k], minlength=n_chains)
                    ids = np.flatnonzero(m)
                    if len(ids):
                        protos.append(hdc_gpu.prototypes(
                            np.asarray(vecs[ids]), m[ids], args.protos, seed + k))
                ps, _ = hdc_gpu.proto_sim(vecs, d_uniq, protos)
                sc[f"{fam}_proto"] = per(d_iid, 1.0 - floor(ps[d_inv]))
            elif want(f"{fam}_proto"):
                protos = []
                for k in range(n_fit):
                    m = np.bincount(sid[di == k], minlength=n_chains)
                    ids = np.flatnonzero(m)
                    if len(ids):
                        protos.append(hdc.prototypes(
                            hdc.unit(vecs[ids]), m[ids].astype(np.float32),
                            args.protos, seed + k,
                            binarize=fam == "hdc"))
                pm = (np.vstack(protos) if protos
                      else np.zeros((0, args.dim), np.float32))
                ps, _ = hdc.max_sim(vecs, pm, q_idx=d_uniq)
                sc[f"{fam}_proto"] = per(d_iid, 1.0 - floor(ps[d_inv]))
            if want(f"{fam}_drift"):
                dr = _drift(vecs, sid, iid, is_d, args.alpha_fast,
                            args.alpha_slow, args.min_sessions)
                sc[f"{fam}_drift"] = per(d_iid, dr[d_idx])
            sc = {d: v for d, v in sc.items() if want(d)}
            del vecs
            path.unlink()
            (tmp / "fit_bundles.npy").unlink(missing_ok=True)
        out[seed] = sc
    return out


def stability(name: str, per_seed: dict[int, dict], k: int, seed: int
              ) -> list[dict]:
    rows = []
    seeds = sorted(per_seed)
    for det in per_seed[seeds[0]]:
        tops = [set(np.flatnonzero(bl.ranks_desc(per_seed[s][det], seed) <= k))
                for s in seeds]
        js = [len(a & b) / max(1, len(a | b))
              for a, b in itertools.combinations(tops, 2)]
        rows.append({"eval_name": name, "detector": det, "k": k,
                     "n_seeds": len(seeds),
                     "jaccard": float(np.mean(js)) if js else 1.0})
    return rows


# ---------------------------------------------------------------- reports

def _table(rows: list[dict], ks: list[int], dets: list[str]) -> list[str]:
    md = []
    for k in ks:
        sub = [r for r in rows if r["k"] == k]
        md += [f"### k = {k}", "",
               "| archetype | n | chance | " + " | ".join(dets) + " |",
               "| --- | ---: | ---: | " + " | ".join("---:" for _ in dets) + " |"]
        keys = list(dict.fromkeys((r["archetype"], r["is_control"]) for r in sub))
        for arch, ctrl in keys:
            cells = {r["detector"]: r for r in sub
                     if r["archetype"] == arch and r["is_control"] == ctrl}
            any_r = next(iter(cells.values()))
            md.append(f"| {arch}{' (control)' if ctrl else ''} | "
                      f"{any_r['n_truth']} | {any_r['chance']:.3f} | " +
                      " | ".join(f"{cells[d]['recall']:.2f}" if d in cells
                                 else "" for d in dets) + " |")
        md.append("")
    return md


def run(args: argparse.Namespace) -> None:
    con = lib.duck()
    lib.register_eval_views(con, args.eval)
    truth = con.execute("SELECT * FROM eval_truth").to_arrow_table().to_pylist()
    day = min(t["start_ts"] for t in truth).astimezone(_dt.timezone.utc).date()
    fit_days = bl._fit_days(con, day, args.fit_days)
    ips = _population(con, day)
    (lib.OUTPUT_DIR / ".hdc_tmp").mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=f"{args.eval}_",
                                dir=lib.OUTPUT_DIR / ".hdc_tmp"))
    try:
        buckets = args.session_buckets or _auto_buckets(con, fit_days + [day])
        print(f"[hdc_eval] sessions in {buckets} source bucket(s)",
              file=sys.stderr)
        sess = _sessions(con, fit_days + [day], args.max_tokens, buckets, tmp)
        con.close()                    # free DuckDB memory before numpy work
        per_seed = score_set(sess, fit_days, ips, args.seeds, args, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    main_seed = args.seeds[0]
    from bench import harness2
    ranks = harness2.truth_ranks(args.eval, day, ips, per_seed[main_seed],
                                 truth, args.seed)
    if args.only:
        # add (or replace) these detectors in the saved ranks; the per-set
        # report and stability files keep the full run's detectors
        old = harness2.OUT / "hdc_eval" / f"{args.eval}_ranks.parquet"
        if old.exists():
            ranks = [r for r in pq.read_table(old).to_pylist()
                     if r["detector"] not in args.only] + ranks
        p = harness2.write_ranks("hdc_eval", args.eval, ranks)
        print(f"[hdc_eval] merged {', '.join(args.only)} into {p}",
              file=sys.stderr)
        return
    rows = bl.eval_source(args.eval, ips, per_seed[main_seed], truth,
                          args.source_k, args.seed)
    harness2.write_ranks("hdc_eval", args.eval, ranks)
    stab = [r for k in args.source_k
            for r in stability(args.eval, per_seed, k, args.seed)]

    dets = list(per_seed[main_seed])
    base = OUT.parent / "baselines" / f"baselines_{args.eval}.parquet"
    if base.exists():
        brows = [r for r in pq.read_table(base).to_pylist()
                 if r["level"] == "source"]
        rows_md = rows + brows
        dets_md = dets + list(dict.fromkeys(r["detector"] for r in brows))
    else:
        rows_md, dets_md = rows, dets
    md = [f"- injection set: `{args.eval}`, scored day {day}",
          f"- fit window: {fit_days[0]} .. {fit_days[-1]} "
          f"({len(fit_days)} recorded days, sensormask applied)",
          f"- scored: {len(ips):,} sources; encoder seed {main_seed}, "
          f"D = {args.dim}, {args.protos} prototypes per fit day", "",
          "Recall at a fixed alert budget, no point adjustment. The "
          "columns after `hdc_drift` are this module's twins; the rest "
          "come from baselines.py on the same set.", "",
          "## Source level", ""]
    md += _table(rows_md, args.source_k, dets_md)
    md += ["## Top-k stability across encoder seeds", "",
           f"Seeds: {', '.join(map(str, args.seeds))}. Mean pairwise "
           "Jaccard of the top-k source sets.", "",
           "| detector | " + " | ".join(f"k = {k}" for k in args.source_k) + " |",
           "| --- | " + " | ".join("---:" for _ in args.source_k) + " |"]
    for det in dets:
        md.append(f"| {det} | " + " | ".join(
            f"{r['jaccard']:.3f}" for k in args.source_k for r in stab
            if r["detector"] == det and r["k"] == k) + " |")
    paths = lib.Report(name="hdc_eval", rows=rows, schema=bl.RESULT_SCHEMA,
                       markdown="\n".join(md) + "\n").write(suffix=args.eval)
    sp = OUT / f"hdc_stability_{args.eval}.parquet"
    pq.write_table(pa.Table.from_pylist(stab, schema=STABILITY_SCHEMA),
                   sp.with_suffix(".parquet.tmp"), compression="zstd")
    sp.with_suffix(".parquet.tmp").replace(sp)
    print(f"[hdc_eval] wrote {paths['parquet']}", file=sys.stderr)


def summary(names: list[str]) -> None:
    """Pool recall over sets: sum(hits) / sum(n_truth) per detector."""
    rows, stab = [], []
    for n in names:
        rows += pq.read_table(OUT / f"hdc_eval_{n}.parquet").to_pylist()
        b = OUT.parent / "baselines" / f"baselines_{n}.parquet"
        if b.exists():
            rows += [r for r in pq.read_table(b).to_pylist()
                     if r["level"] == "source"]
        stab += pq.read_table(OUT / f"hdc_stability_{n}.parquet").to_pylist()
    agg: dict[tuple, dict] = {}
    for r in rows:
        key = (r["detector"], r["archetype"], r["is_control"], r["k"])
        a = agg.setdefault(key, {"detector": key[0], "archetype": key[1],
                                 "is_control": key[2], "k": key[3],
                                 "sets": set(), "n_truth": 0, "hits": 0,
                                 "chance_w": 0.0})
        a["sets"].add(r["eval_name"])
        a["n_truth"] += r["n_truth"]
        a["hits"] += r["hits"]
        a["chance_w"] += r["chance"] * r["n_truth"]
    out = [{"detector": a["detector"], "archetype": a["archetype"],
            "is_control": a["is_control"], "k": a["k"],
            "n_sets": len(a["sets"]), "n_truth": a["n_truth"],
            "hits": a["hits"], "recall": a["hits"] / max(1, a["n_truth"]),
            "chance": a["chance_w"] / max(1, a["n_truth"])}
           for a in agg.values()]
    ks = sorted({r["k"] for r in out})
    dets = list(dict.fromkeys(r["detector"] for r in out))
    md = [f"- pooled over {len(names)} injection sets: "
          f"{', '.join(f'`{n}`' for n in names)}",
          "- recall = total hits / total injected sources", "",
          "## Source level (pooled)", ""]
    md += _table(out, ks, dets)
    md += ["## Top-k stability (mean over sets)", "",
           "| detector | k | Jaccard |", "| --- | ---: | ---: |"]
    for det in dict.fromkeys(r["detector"] for r in stab):
        for k in ks:
            js = [r["jaccard"] for r in stab
                  if r["detector"] == det and r["k"] == k]
            if js:
                md.append(f"| {det} | {k} | {np.mean(js):.3f} |")
    lib.Report(name="hdc_eval", rows=out, schema=SUMMARY_SCHEMA,
               markdown="\n".join(md) + "\n").write(suffix="summary")
    print(f"[hdc_eval] wrote {OUT}/hdc_eval_summary.md", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--eval", metavar="NAME",
                    help="adversarysim --inject set to score.")
    ap.add_argument("--summary", nargs="+", metavar="NAME",
                    help="Pool saved hdc_eval/baselines sets instead.")
    ap.add_argument("--fit-days", type=int, default=7)
    ap.add_argument("--source-k", type=int, nargs="+", default=[10, 100, 1000])
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3],
                    help="Encoder seeds; the first one is scored, all of "
                         "them feed the stability check.")
    ap.add_argument("--seed", type=int, default=20261023,
                    help="Tie-break seed (same as baselines.py).")
    ap.add_argument("--dim", type=int, default=hdc.D_DEFAULT)
    ap.add_argument("--noise-z", type=float, default=5.0,
                    help="HDC cosine at or below this many noise sigmas "
                         "(1/sqrt(D)) counts as no similarity.")
    ap.add_argument("--protos", type=int, default=128,
                    help="Sub-prototypes per fit day.")
    ap.add_argument("--max-tokens", type=int, default=30,
                    help="Tokens per session (chainfp default).")
    ap.add_argument("--alpha-fast", type=float, default=0.5)
    ap.add_argument("--alpha-slow", type=float, default=0.05)
    ap.add_argument("--min-sessions", type=int, default=3)
    ap.add_argument("--session-buckets", type=int, default=0,
                    help="hash(src_ip) buckets for the session query "
                         "(0 = one for each 4M packets).  More buckets = "
                         "less DuckDB memory, same rows.")
    ap.add_argument("--align-power", type=float, default=4.0,
                    help="Exponent p on the bundle cosine in *_align.")
    ap.add_argument("--align-weight", choices=("distinct", "count"),
                    default="distinct",
                    help="Source bundle: each distinct chain once, or "
                         "weighted by its session count.")
    ap.add_argument("--device", choices=("cpu", "gpu"), default="cpu",
                    help="gpu: HDC encode, hdc_proto k-means and search on "
                         "the GPU (sg.hdc_gpu; encode bit-exact, proto close)")
    ap.add_argument("--only", nargs="+", metavar="DET", default=None,
                    help="Score only these detectors (and the first "
                         "--seeds seed) and merge their rows into the "
                         "set's saved harness2 ranks.")
    args = ap.parse_args()
    if args.only:
        bad = set(args.only) - set(DETECTORS)
        if bad:
            ap.error(f"unknown detector(s): {', '.join(sorted(bad))}")
        args.seeds = args.seeds[:1]
    if args.summary:
        summary(args.summary)
    elif args.eval:
        run(args)
    else:
        ap.error("give --eval NAME or --summary NAME ...")
    return 0


if __name__ == "__main__":
    sys.exit(main())

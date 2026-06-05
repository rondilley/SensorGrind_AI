#!/usr/bin/env python3
"""
httppatterns — cluster HTTP request payloads into human-readable attack
templates (Track B: representation-based payload pattern mining).

Graduated from the bench feasibility work (bench/payload_spike +
bench/http_pattern_pilot). The spike showed whole-corpus payload embedding is
infeasible (99% high-entropy binary/encrypted), but HTTP is small and
text-templatable: ~712k payloads / ~571k DISTINCT with very low exact-skew
(top-50k distinct cover only ~20% of volume). Classical exact/prefix clustering
(trafficprint) therefore leaves HTTP mostly un-templated, because attack
requests embed unique tokens (random params, cache-busters, per-host paths).

Clustering is on the REQUEST LINE only (method + path + query) — NOT headers.
Header content (User-Agent, Host, ordering) is attacker-controlled, trivially
spoofed, and is exactly what JA4H already fingerprints; letting it drive these
clusters just re-derives a client fingerprint. The attack intent lives in the
request line, so that is what we templatize.

Pipeline (dependency-light: sklearn + hdbscan, no torch / model download — a
sentence-transformer encoder can be swapped in later, same shape):

    request lines of intent-bearing HTTP requests
      -> TF-IDF char n-grams (structure survives unique tokens)
      -> TruncatedSVD (dense, denoised)
      -> HDBSCAN (density clusters, noise-aware)
      -> per-cluster token-alignment template ("POST /boaform/admin/formLogin")

Outputs (Report contract): output/reports/http_patterns/http_patterns.{parquet,md}
plus summary.json (headline coverage stats, read by bench/compute_metrics).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib

HTTP_PROTO = 1
METHOD_RE = re.compile(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s",
                       re.IGNORECASE)

OUT_DIR = lib.REPORTS / "http_patterns"

RESULT_SCHEMA = pa.schema([
    ("cluster_id",      pa.int32()),
    ("template",        pa.string()),
    ("distinct_count",  pa.uint32()),   # distinct payloads assigned to cluster
    ("volume",          pa.uint64()),   # total occurrences (weighted)
    ("coverage_share",  pa.float32()),  # share of clustered volume
    ("novel",           pa.bool_()),    # path NOT matched by any probesigs signature
    ("sample_request",  pa.string()),
])

PROBESIGS_PATH = lib.REPORTS / "probesigs" / "probesigs.parquet"

# Per-payload cluster membership — the join key that lets correlate roll HTTP
# templates up to source IPs (via l7_events.payload_sha256) and lets attackmap
# map templates to techniques. fixed_size_binary[32] matches payload_blobs /
# l7_events.payload_sha256 so DuckDB joins cleanly.
MEMBERSHIP_SCHEMA = pa.schema([
    ("payload_sha256", pa.binary(32)),
    ("cluster_id",     pa.int32()),
])
MEMBERSHIP_PATH = OUT_DIR / "payload_clusters.parquet"


# ---------------------------------------------------------------- pure helpers

def first_line(text: str) -> str:
    """The HTTP request line (or first line) — what we templatize."""
    return text.split("\r\n", 1)[0].split("\n", 1)[0].strip()


def generalize_requests(lines: list[str], min_share: float = 0.6) -> str:
    """Token-align a cluster's request lines into one template with '*' for
    variable segments.  Pure/string-only so it unit-tests without the corpus.

    'GET /a/1 HTTP/1.1', 'GET /a/2 HTTP/1.1' -> 'GET /a/*'
    """
    parsed = []
    for ln in lines:
        parts = ln.split(" ")
        if len(parts) >= 2 and METHOD_RE.match(parts[0].encode("latin-1", "ignore") + b" "):
            method = parts[0].upper()
            target = parts[1]
            parsed.append((method, target))
    if not parsed:
        # not parseable as HTTP request lines — fall back to a shared prefix
        return _common_prefix(lines) or "(non-standard)"

    n = len(parsed)
    method = Counter(m for m, _ in parsed).most_common(1)[0][0]

    has_query = sum("?" in t for _, t in parsed) / n >= 0.5
    paths = [t.split("?", 1)[0] for _, t in parsed]
    seg_lists = [p.strip("/").split("/") for p in paths]
    width = Counter(len(s) for s in seg_lists).most_common(1)[0][0]

    out_segs = []
    for i in range(width):
        vals = [s[i] for s in seg_lists if len(s) > i]
        if not vals:
            continue
        top, cnt = Counter(vals).most_common(1)[0]
        out_segs.append(top if cnt / len(vals) >= min_share else "*")
    path_tmpl = "/" + "/".join(out_segs)
    return f"{method} {path_tmpl}{'?*' if has_query else ''}"


def _common_prefix(strings: list[str]) -> str:
    if not strings:
        return ""
    s1, s2 = min(strings), max(strings)
    i = 0
    while i < len(s1) and i < len(s2) and s1[i] == s2[i]:
        i += 1
    return s1[:i].rstrip()


# ---------------------------------------------------------------- pipeline

def load_http(con, max_len: int = 512):
    """Distinct *intent-bearing* HTTP payloads: sha256 + text prefix + weight.

    Excludes EVERY trivial-root request (`METHOD /` — GET/POST/OPTIONS/...),
    not just `GET /`.  On an ultra-low-interaction sensor these carry no
    request-line intent; their only discriminator is the client header set,
    which JA4H already fingerprints.  We keep only requests whose intent is IN
    the request line — a real path, query, or traversal — which a low-
    interaction sensor captures in full (the URI/method *is* the one-shot
    payload)."""
    rows = con.execute(f"""
        SELECT payload_sha256,
               any_value(bytes[1:{max_len}]) AS b,
               count(*) AS w
        FROM payload_blobs
        WHERE l7_proto = {HTTP_PROTO} AND payload_len >= 8
          AND NOT regexp_matches(CAST(bytes[1:160] AS VARCHAR),
                                 '^[A-Z]{{3,8}} /[ \\r\\n]')
        GROUP BY payload_sha256
    """).fetchall()
    shas = [bytes(r[0]) for r in rows]
    texts = [bytes(r[1]).decode("latin-1", "ignore") for r in rows]
    weights = np.array([r[2] for r in rows], dtype=np.int64)
    return shas, texts, weights


def known_probe_uris() -> set[str]:
    """probesigs' curated known-bad URI signatures, lowercased. A template
    whose path matches none of these is a *novel* discovery (probesigs is
    signature-based and only catches its hardcoded list)."""
    if not PROBESIGS_PATH.exists() or PROBESIGS_PATH.stat().st_size == 0:
        return set()
    uris = pq.read_table(PROBESIGS_PATH, columns=["uri"]).column("uri").to_pylist()
    return {u.lower() for u in uris if u}


def template_path(tmpl: str) -> str:
    """Extract the path token from a 'METHOD /path  [UA: ...]' template."""
    body = tmpl.split("  [", 1)[0]
    parts = body.split(" ", 1)
    return parts[1] if len(parts) > 1 else body


def is_novel(tmpl: str, known: set[str]) -> bool:
    """True if the template's path matches no probesigs signature."""
    path = template_path(tmpl).lower()
    return not any(u in path for u in known)


def _write_summary(summary: dict) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2))


def _write_membership(membership: list[tuple[bytes, int]]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tbl = pa.table({
        "payload_sha256": pa.array([m[0] for m in membership], pa.binary(32)),
        "cluster_id":     pa.array([m[1] for m in membership], pa.int32()),
    }, schema=MEMBERSHIP_SCHEMA)
    pq.write_table(tbl, MEMBERSHIP_PATH, compression="zstd", compression_level=3)


def run(args: argparse.Namespace) -> lib.Report:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import TruncatedSVD
    from sklearn.preprocessing import normalize
    import hdbscan

    con = lib.duck(memory_limit=lib.auto_memory_limit(fraction=0.4, min_gb=4))
    lib.register_views(con)
    print("[httppatterns] loading distinct HTTP payloads...", file=sys.stderr)
    shas, texts, weights = load_http(con)
    con.close()
    n_total = len(texts)
    print(f"[httppatterns] {n_total:,} distinct intent-bearing HTTP payloads",
          file=sys.stderr)
    if n_total < 50:
        rep = lib.Report(name="http_patterns", rows=[], schema=RESULT_SCHEMA,
                         markdown="_Too few HTTP payloads to cluster._\n")
        rep.summary = {"distinct_payloads": n_total, "clusters": 0,
                       "coverage_estimate": None}
        rep.membership = []
        return rep

    # Cluster on the REQUEST LINE only — headers (UA/Host/ordering) are
    # attacker-controlled and already covered by JA4H, so they must not drive
    # these clusters. The request line carries the attack intent.
    req_lines = [first_line(t) for t in texts]

    # Cluster a bounded sample (HDBSCAN cost), then assign the rest by nearest
    # centroid for per-template volume weighting.
    rng = np.random.default_rng(42)
    sample_n = min(args.cluster_sample, n_total)
    sample_idx = rng.choice(n_total, size=sample_n, replace=False)
    sample_lines = [req_lines[i] for i in sample_idx]
    if sample_n < n_total:
        print(f"[httppatterns] clustering a {sample_n:,} sample of {n_total:,} "
              f"(NOT silently capped — rest assigned by nearest centroid)",
              file=sys.stderr)

    print("[httppatterns] vectorizing request lines (char 3-5 grams) + SVD...",
          file=sys.stderr)
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                          min_df=3, max_features=40000)
    X_sample = vec.fit_transform(sample_lines)
    svd = TruncatedSVD(n_components=args.svd_dims, random_state=42)
    Z_sample = normalize(svd.fit_transform(X_sample))

    print(f"[httppatterns] HDBSCAN on {sample_n:,} x {args.svd_dims}d...",
          file=sys.stderr)
    clusterer = hdbscan.HDBSCAN(min_cluster_size=args.min_cluster_size,
                                min_samples=args.min_samples,
                                metric="euclidean", core_dist_n_jobs=-1)
    labels = clusterer.fit_predict(Z_sample)
    n_clusters = len({l for l in labels if l != -1})
    sample_clustered = int((labels != -1).sum())
    # The random sample is representative of the full distinct set, so its
    # density-clustered fraction is the HONEST estimate of HTTP coverage.
    # (Nearest-centroid assignment below would trivially reach ~100% at a loose
    # threshold — that's a gamed number, not coverage.)
    coverage_est = sample_clustered / sample_n
    print(f"[httppatterns] {n_clusters} clusters; "
          f"HTTP coverage estimate {coverage_est*100:.1f}% "
          f"(sample clustered; {sample_n - sample_clustered:,} noise)",
          file=sys.stderr)

    # Cluster centroids in SVD space, for assigning the full distinct set.
    centroids, cids = [], []
    for cid in sorted(l for l in set(labels) if l != -1):
        centroids.append(Z_sample[labels == cid].mean(axis=0))
        cids.append(cid)
    centroids = normalize(np.vstack(centroids)) if centroids else np.zeros((0, args.svd_dims))

    # Assign the full distinct set to nearest centroid ONLY to weight each
    # template by real occurrence volume (for ranking). A cosine gate keeps this
    # from being presented as a coverage number.
    print("[httppatterns] weighting templates by full-corpus volume...",
          file=sys.stderr)
    Z_all = normalize(svd.transform(vec.transform(req_lines)))
    if len(centroids):
        sims = Z_all @ centroids.T              # cosine (both normalized)
        best = sims.argmax(axis=1)
        best_sim = sims[np.arange(len(texts)), best]
        assigned = best_sim >= args.assign_min_cos
        assign_cid = np.where(assigned, np.array(cids)[best], -1)
    else:
        assign_cid = np.full(len(texts), -1)
        assigned = np.zeros(len(texts), dtype=bool)

    total_vol = int(weights.sum())
    covered_vol = int(weights[assigned].sum())
    known = known_probe_uris()

    rows = []
    for cid in cids:
        members = [sample_lines[i] for i in np.where(labels == cid)[0]]
        tmpl = generalize_requests(members)  # request lines only — no headers
        mask = assign_cid == cid
        vol = int(weights[mask].sum())
        rows.append({
            "cluster_id": int(cid),
            "template": tmpl,
            "distinct_count": int(mask.sum()),
            "volume": vol,
            "coverage_share": float(vol / covered_vol) if covered_vol else 0.0,
            "novel": is_novel(tmpl, known),
            "sample_request": members[0][:160],
        })
    rows.sort(key=lambda r: r["volume"], reverse=True)
    novel_clusters = sum(1 for r in rows if r["novel"])
    novel_volume = sum(r["volume"] for r in rows if r["novel"])

    md = _render_md(rows, n_total, n_clusters, sample_n, sample_clustered,
                    coverage_est, covered_vol, total_vol, novel_clusters,
                    novel_volume, args)
    rep = lib.Report(name="http_patterns", rows=rows, schema=RESULT_SCHEMA,
                     markdown=md)
    # Stash headline stats on the Report; main() persists them (run() stays
    # side-effect-free so callers/tests don't clobber real outputs).
    rep.summary = {
        "scope": "intent_bearing_http",  # bare 'GET /' excluded (see load_http)
        "distinct_payloads": n_total,
        "clusters": n_clusters,
        "novel_clusters": novel_clusters,        # not matched by any probesigs sig
        "novel_volume": int(novel_volume),
        "sample_n": sample_n,
        "sample_clustered": sample_clustered,
        "coverage_estimate": round(coverage_est, 4),
        "volume_covered": covered_vol,
        "volume_total": total_vol,
    }
    # Per-payload membership for downstream join (correlate/attackmap): every
    # distinct payload assigned to a cluster (>= assign_min_cos).
    rep.membership = [(shas[i], int(assign_cid[i]))
                      for i in range(n_total) if assign_cid[i] != -1]
    return rep


def _render_md(rows, n_total, n_clusters, sample_n, sample_clustered,
               coverage_est, covered_vol, total_vol, novel_clusters,
               novel_volume, args) -> str:
    def pct(a, b):
        return f"{a/b*100:.1f}%" if b else "n/a"
    lines = [
        "## HTTP request templates (embedding-style clustering)",
        "",
        "_Scope: **intent-bearing** HTTP only — the bare `GET /` root probe "
        "(~75% of HTTP on this ultra-low-interaction sensor) is excluded; its "
        "only signal is the client header set, already covered by JA4H. We "
        "cluster requests whose intent is in the request line (exploit URIs, "
        "non-GET methods, queries, traversal), which a low-interaction sensor "
        "captures in full._",
        "",
        f"- distinct intent-bearing HTTP payloads: **{n_total:,}**",
        f"- clusters found: **{n_clusters}** "
        f"(min_cluster_size={args.min_cluster_size}, char 3-5 grams, "
        f"SVD {args.svd_dims}d)",
        f"- **novel templates** (no `probesigs` signature): **{novel_clusters}** "
        f"of {n_clusters} — the marginal discovery over hand-written signatures",
        f"- coverage estimate: {pct(sample_clustered, sample_n)} of the "
        f"intent-bearing sample falls into a recurring template",
        "",
        "### Top templates by volume", "",
        "| # | template | distinct | volume | novel |",
        "| --- | --- | --- | --- | --- |",
    ]
    for i, r in enumerate(rows[:args.limit_templates], 1):
        tmpl = r["template"].replace("|", "\\|")[:80]
        lines.append(f"| {i} | `{tmpl}` | {r['distinct_count']:,} | "
                     f"{r['volume']:,} | {'yes' if r['novel'] else ''} |")
    if len(rows) > args.limit_templates:
        lines.append(f"\n_…{len(rows) - args.limit_templates} more templates._")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    ap.add_argument("--cluster-sample", type=int, default=60000,
                    help="Max distinct payloads to run HDBSCAN on (default 60k).")
    ap.add_argument("--min-cluster-size", type=int, default=8)
    ap.add_argument("--min-samples", type=int, default=4)
    ap.add_argument("--svd-dims", type=int, default=40)
    ap.add_argument("--assign-min-cos", type=float, default=0.5,
                    help="Min cosine to assign a payload to a cluster centroid.")
    ap.add_argument("--limit-templates", type=int, default=40)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    _write_summary(report.summary)
    _write_membership(report.membership)
    print(f"[httppatterns] wrote {paths['parquet']}")
    print(f"[httppatterns] wrote {paths['markdown']}")
    print(f"[httppatterns] wrote {MEMBERSHIP_PATH} "
          f"({len(report.membership):,} payload assignments)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

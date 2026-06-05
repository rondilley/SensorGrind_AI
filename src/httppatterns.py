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

Pipeline (dependency-light: sklearn + hdbscan, no torch / model download — a
sentence-transformer encoder can be swapped in later, same shape):

    distinct HTTP payloads
      -> TF-IDF char n-grams (structure survives unique tokens)
      -> TruncatedSVD (dense, denoised)
      -> HDBSCAN (density clusters, noise-aware)
      -> per-cluster token-alignment template + dominant UA/Host

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib

HTTP_PROTO = 1
METHOD_RE = re.compile(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s",
                       re.IGNORECASE)
UA_RE = re.compile(r"User-Agent:\s*(.+)", re.IGNORECASE)
HOST_RE = re.compile(r"Host:\s*(.+)", re.IGNORECASE)

OUT_DIR = lib.REPORTS / "http_patterns"

RESULT_SCHEMA = pa.schema([
    ("cluster_id",      pa.int32()),
    ("template",        pa.string()),
    ("distinct_count",  pa.uint32()),   # distinct payloads assigned to cluster
    ("volume",          pa.uint64()),   # total occurrences (weighted)
    ("coverage_share",  pa.float32()),  # share of clustered volume
    ("sample_request",  pa.string()),
])


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


def dominant_header(texts: list[str], regex: re.Pattern,
                    min_share: float = 0.3) -> str | None:
    """Most common header value across a cluster's full payloads, if it
    dominates. Used to distinguish clusters whose request lines are identical
    (e.g. many 'GET /' probes separated only by their User-Agent / tool)."""
    vals = [m.group(1).strip().rstrip("\r")
            for t in texts if (m := regex.search(t))]
    if not vals:
        return None
    val, cnt = Counter(vals).most_common(1)[0]
    return val if cnt / len(texts) >= min_share else None


def _common_prefix(strings: list[str]) -> str:
    if not strings:
        return ""
    s1, s2 = min(strings), max(strings)
    i = 0
    while i < len(s1) and i < len(s2) and s1[i] == s2[i]:
        i += 1
    return s1[:i].rstrip()


# ---------------------------------------------------------------- pipeline

def load_http(con, max_len: int = 512) -> tuple[list[str], np.ndarray]:
    """Distinct HTTP payloads (text prefix) + occurrence weight."""
    rows = con.execute(f"""
        SELECT any_value(bytes[1:{max_len}]) AS b, count(*) AS w
        FROM payload_blobs
        WHERE l7_proto = {HTTP_PROTO} AND payload_len >= 8
        GROUP BY payload_sha256
    """).fetchall()
    texts = [bytes(b).decode("latin-1", "ignore") for b, _ in rows]
    weights = np.array([w for _, w in rows], dtype=np.int64)
    return texts, weights


def _write_summary(summary: dict) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2))


def run(args: argparse.Namespace) -> lib.Report:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import TruncatedSVD
    from sklearn.preprocessing import normalize
    import hdbscan

    con = lib.duck(memory_limit=lib.auto_memory_limit(fraction=0.4, min_gb=4))
    lib.register_views(con)
    print("[httppatterns] loading distinct HTTP payloads...", file=sys.stderr)
    texts, weights = load_http(con)
    con.close()
    n_total = len(texts)
    print(f"[httppatterns] {n_total:,} distinct HTTP payloads", file=sys.stderr)
    if n_total < 50:
        rep = lib.Report(name="http_patterns", rows=[], schema=RESULT_SCHEMA,
                         markdown="_Too few HTTP payloads to cluster._\n")
        rep.summary = {"distinct_payloads": n_total, "clusters": 0,
                       "coverage_estimate": None}
        return rep

    # Cluster a bounded sample (HDBSCAN cost), then assign the rest by nearest
    # centroid for per-template volume weighting.
    rng = np.random.default_rng(42)
    sample_n = min(args.cluster_sample, n_total)
    sample_idx = rng.choice(n_total, size=sample_n, replace=False)
    sample_texts = [texts[i] for i in sample_idx]
    if sample_n < n_total:
        print(f"[httppatterns] clustering a {sample_n:,} sample of {n_total:,} "
              f"(NOT silently capped — rest assigned by nearest centroid)",
              file=sys.stderr)

    print("[httppatterns] vectorizing (char 3-5 grams) + SVD...", file=sys.stderr)
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                          min_df=3, max_features=40000)
    X_sample = vec.fit_transform(sample_texts)
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
    Z_all = normalize(svd.transform(vec.transform(texts)))
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

    rows = []
    for cid in cids:
        members = [sample_texts[i] for i in np.where(labels == cid)[0]]
        tmpl = generalize_requests([first_line(t) for t in members])
        # Many clusters share a bare request line ("GET /") and differ only by
        # headers; surface the dominant UA (always) and Host (when the path is
        # uninformative) so the template is interpretable.
        extras = []
        ua = dominant_header(members, UA_RE, min_share=0.25)
        if ua:
            extras.append(f"UA: {ua[:36]}")
        if tmpl.rstrip().endswith("/"):
            host = dominant_header(members, HOST_RE, min_share=0.4)
            if host:
                extras.append(f"Host: {host[:30]}")
        if extras:
            tmpl += "  [" + "; ".join(extras) + "]"
        mask = assign_cid == cid
        vol = int(weights[mask].sum())
        rows.append({
            "cluster_id": int(cid),
            "template": tmpl,
            "distinct_count": int(mask.sum()),
            "volume": vol,
            "coverage_share": float(vol / covered_vol) if covered_vol else 0.0,
            "sample_request": first_line(members[0])[:160],
        })
    rows.sort(key=lambda r: r["volume"], reverse=True)

    md = _render_md(rows, n_total, n_clusters, sample_n, sample_clustered,
                    coverage_est, covered_vol, total_vol, args)
    rep = lib.Report(name="http_patterns", rows=rows, schema=RESULT_SCHEMA,
                     markdown=md)
    # Stash headline stats on the Report; main() persists them (run() stays
    # side-effect-free so callers/tests don't clobber real outputs).
    rep.summary = {
        "distinct_payloads": n_total,
        "clusters": n_clusters,
        "sample_n": sample_n,
        "sample_clustered": sample_clustered,
        "coverage_estimate": round(coverage_est, 4),
        "volume_covered": covered_vol,
        "volume_total": total_vol,
    }
    return rep


def _render_md(rows, n_total, n_clusters, sample_n, sample_clustered,
               coverage_est, covered_vol, total_vol, args) -> str:
    def pct(a, b):
        return f"{a/b*100:.1f}%" if b else "n/a"
    lines = [
        "## HTTP request templates (embedding-style clustering)",
        "",
        f"- distinct HTTP payloads: **{n_total:,}**",
        f"- clusters found: **{n_clusters}** "
        f"(min_cluster_size={args.min_cluster_size}, char 3-5 grams, "
        f"SVD {args.svd_dims}d)",
        f"- **HTTP coverage estimate: {pct(sample_clustered, sample_n)}** "
        f"(density-clustered fraction of a representative {sample_n:,} sample; "
        f"the rest is HDBSCAN noise = genuinely one-off / unique requests)",
        f"- template volume weighting covers {pct(covered_vol, total_vol)} of "
        f"HTTP occurrences (nearest-centroid @cos>={args.assign_min_cos}; "
        f"used only for ranking, not as a coverage claim)",
        "",
        "_Why this matters: exact/prefix methods (trafficprint) leave HTTP "
        "mostly un-templated — the top-50k of 571k distinct payloads cover only "
        "~20% of HTTP volume because attack requests embed unique tokens "
        "(random params, cache-busters, per-host paths). Structural clustering "
        f"recovers ~{pct(sample_clustered, sample_n)} as {n_clusters} reusable "
        "templates._",
        "",
        "### Top templates by volume", "",
        "| # | template | distinct | volume | share |",
        "| --- | --- | --- | --- | --- |",
    ]
    for i, r in enumerate(rows[:args.limit_templates], 1):
        tmpl = r["template"].replace("|", "\\|")[:80]
        lines.append(f"| {i} | `{tmpl}` | {r['distinct_count']:,} | "
                     f"{r['volume']:,} | {r['coverage_share']*100:.1f}% |")
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
    print(f"[httppatterns] wrote {paths['parquet']}")
    print(f"[httppatterns] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
mining/promote_patterns — hybrid pattern promotion (vectorized).

Hybrid rules:
  - BEHAVIORAL patterns (only port:/asn:/cc:/l7: tokens) auto-promote
    when ip_count >= MIN_IPS and threat-purity >= MIN_PURITY.
  - CONTENT patterns (any ua:/uri:/bot: token) go to a review queue.

Threat purity = fraction of IPs matching the itemset that are at or
above the "medium" risk tier.

Performance: builds a CSR sparse (ip x token) boolean matrix once,
then evaluates each itemset by AND-reducing the relevant columns -
two orders of magnitude faster than Python set lookups.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import scipy.sparse as sp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
PAT_DIR = lib.OUTPUT_DIR / "patterns"

BEHAVIORAL_PREFIXES = ("port:", "asn:", "cc:", "l7:")
CONTENT_PREFIXES = ("ua:", "uri:", "bot:")

RESULT_SCHEMA = pa.schema([
    ("rule_id",      pa.string()),
    ("itemset",      pa.list_(pa.string())),
    ("itemset_str",  pa.string()),
    ("kind",         pa.string()),
    ("disposition",  pa.string()),
    ("ip_count",     pa.uint32()),
    ("threat_pct",   pa.float32()),
    ("avg_risk",     pa.float32()),
    ("sample_ips",   pa.string()),
])


def classify_itemset(items: list[str]) -> str:
    if any(it.startswith(CONTENT_PREFIXES) for it in items):
        return "content"
    if all(it.startswith(BEHAVIORAL_PREFIXES) for it in items):
        return "behavioral"
    return "content"


def build_ip_token_matrix(con) -> tuple[list[str], dict[str, int], sp.csc_matrix]:
    """Build a sparse (n_ips, n_tokens) boolean matrix.

    Returns (ip_list, token->col_index, matrix in CSC for fast column slicing).
    """
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        raise RuntimeError("no ip features")
    feat_path = sf.snapshot_dir(snap) / "part-0000.parquet"

    print("[promote] collecting tokens per IP from DuckDB...", file=sys.stderr)
    rows_iter: list[tuple[str, str]] = []

    # ports (only those an IP hit at least 5 times)
    port_rows = con.execute("""
        SELECT src_ip, dst_port FROM packets
        GROUP BY src_ip, dst_port HAVING count(*) >= 5
    """).fetchall()
    rows_iter.extend((ip, f"port:{p}") for ip, p in port_rows if p is not None)
    print(f"[promote]   port tokens: {len(port_rows):,}", file=sys.stderr)

    # L7 protos
    l7_rows = con.execute("""
        SELECT src_ip, l7_proto FROM l7_events GROUP BY src_ip, l7_proto
    """).fetchall()
    rows_iter.extend((ip, f"l7:{lib.L7_NAME.get(p, 'unknown')}") for ip, p in l7_rows)

    # cc + asn
    geo = con.execute(f"""
        SELECT src_ip, country_iso, asn FROM read_parquet('{feat_path}')
    """).fetchall()
    for ip, cc, asn in geo:
        if cc: rows_iter.append((ip, f"cc:{cc}"))
        if asn: rows_iter.append((ip, f"asn:{asn}"))

    # user-agents (hashed to match miner)
    import hashlib
    ua_rows = con.execute(f"""
        SELECT src_ip, value FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['user_agent']}
        GROUP BY src_ip, value
    """).fetchall()
    for ip, ua in ua_rows:
        h = hashlib.md5((ua or "").encode()).hexdigest()[:8]
        rows_iter.append((ip, f"ua:{h}"))

    # probe tags (from probesigs join with iocs http_uri)
    probes_path = lib.REPORTS / "probesigs" / "probesigs.parquet"
    if probes_path.exists() and probes_path.stat().st_size > 0:
        probe_tags = con.execute(f"""
            SELECT i.src_ip, p.probe_tag FROM iocs i
            JOIN read_parquet('{probes_path}') p ON i.value = p.uri
            WHERE i.ioc_kind = {lib.IOC_ID['http_uri']}
            GROUP BY i.src_ip, p.probe_tag
        """).fetchall()
        rows_iter.extend((ip, f"uri:{tag}") for ip, tag in probe_tags)

    # botnet families
    bot_path = lib.REPORTS / "botnetcls" / "botnetcls.parquet"
    if bot_path.exists() and bot_path.stat().st_size > 0:
        bot_rows = con.execute(f"""
            SELECT DISTINCT p.src_ip, b.family
            FROM read_parquet('{bot_path}') b
            JOIN packets p ON p.payload_sha256 = b.payload_sha256
        """).fetchall()
        rows_iter.extend((ip, f"bot:{f}") for ip, f in bot_rows)

    print(f"[promote] total (ip, token) pairs: {len(rows_iter):,}", file=sys.stderr)

    # Build index maps and CSR matrix.
    ip_to_row: dict[str, int] = {}
    token_to_col: dict[str, int] = {}
    rs = np.empty(len(rows_iter), dtype=np.int32)
    cs = np.empty(len(rows_iter), dtype=np.int32)
    for i, (ip, tok) in enumerate(rows_iter):
        r = ip_to_row.get(ip)
        if r is None:
            r = len(ip_to_row); ip_to_row[ip] = r
        c = token_to_col.get(tok)
        if c is None:
            c = len(token_to_col); token_to_col[tok] = c
        rs[i] = r; cs[i] = c

    vals = np.ones(len(rows_iter), dtype=np.uint8)
    mat = sp.coo_matrix((vals, (rs, cs)),
                        shape=(len(ip_to_row), len(token_to_col))).tocsc()
    # Deduplicate (multiple rows for same (ip,token) -> still nonzero).
    mat.data[:] = 1
    ip_list = [None] * len(ip_to_row)
    for ip, r in ip_to_row.items():
        ip_list[r] = ip
    print(f"[promote] matrix: {mat.shape[0]:,} IPs x {mat.shape[1]:,} tokens, "
          f"{mat.nnz:,} nonzeros", file=sys.stderr)
    return ip_list, token_to_col, mat


def run(args: argparse.Namespace) -> int:
    itemsets_path = PAT_DIR / "itemsets.parquet"
    if not itemsets_path.exists():
        print("[promote] no mined itemsets - run mining/mine_itemsets.py first", file=sys.stderr)
        return 2

    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[promote] no ip features", file=sys.stderr)
        return 2

    risk_path = lib.OUTPUT_DIR / "risk" / "ip_risk" / f"dt={snap.snapshot_date.isoformat()}" / "risk.parquet"
    if not risk_path.exists():
        print(f"[promote] no risk file at {risk_path}", file=sys.stderr)
        return 2

    con = lib.duck(memory_limit="8GB")
    lib.register_views(con)

    # Threat IPs (medium+)
    print("[promote] loading risk tiers...", file=sys.stderr)
    risk_rows = con.execute(f"""
        SELECT src_ip, risk_score, risk_tier FROM read_parquet('{risk_path}')
    """).fetchall()
    threat_score: dict[str, float] = {
        r[0]: float(r[1]) for r in risk_rows if r[2] in ("critical", "high", "medium")
    }
    print(f"[promote] {len(threat_score):,} threat IPs", file=sys.stderr)

    ip_list, token_to_col, mat = build_ip_token_matrix(con)
    threat_mask = np.array(
        [1 if ip in threat_score else 0 for ip in ip_list], dtype=np.int8
    )
    threat_score_arr = np.array(
        [threat_score.get(ip, 0.0) for ip in ip_list], dtype=np.float32
    )

    # Itemsets
    itemsets_rows = con.execute(f"""
        SELECT itemset, support_pct, ip_count, itemset_str, size
        FROM read_parquet('{itemsets_path}')
        ORDER BY ip_count DESC
    """).fetchall()
    con.close()
    print(f"[promote] evaluating {len(itemsets_rows):,} itemsets...", file=sys.stderr)

    out_rows: list[dict] = []
    auto_count = queued_count = skipped = unknown_tok = 0

    # Convert to CSR once for fast row reductions; we'll slice columns on CSC.
    mat_csc = mat
    n_ips = mat_csc.shape[0]

    for idx, (itemset, support_pct, ip_count, itemset_str, size) in enumerate(itemsets_rows):
        if idx and idx % 50_000 == 0:
            print(f"[promote]   {idx:,}/{len(itemsets_rows):,} "
                  f"(auto={auto_count} queued={queued_count})", file=sys.stderr)
        items = list(itemset)
        if len(items) < 2:
            continue

        cols = [token_to_col.get(it) for it in items]
        if any(c is None for c in cols):
            unknown_tok += 1
            continue

        # AND-reduce the selected columns -> bool array of matching IPs.
        sub = mat_csc[:, cols].toarray().astype(bool)  # (n_ips, len(items))
        match = sub.all(axis=1)
        n_match = int(match.sum())
        if n_match < args.min_ips:
            skipped += 1
            continue

        kind = classify_itemset(items)
        threat_match = int((match & (threat_mask == 1)).sum())
        threat_pct = threat_match / n_match if n_match else 0.0
        avg_risk = float(threat_score_arr[match].mean()) if n_match else 0.0

        # Wilson lower-bound on the threat fraction (Agresti-Coull): a
        # 43/50 itemset has a much weaker statistical claim than an
        # 850/1000 itemset even though both are 86% purity.  Gate
        # promotion on the lower bound rather than the point estimate
        # so small-support rules need higher observed purity to qualify.
        # z=1.96 corresponds to 95% confidence.
        z = 1.96
        denom = 1 + z * z / n_match if n_match else 1.0
        center = (threat_pct + z * z / (2 * n_match)) / denom
        margin = z * (
            (threat_pct * (1 - threat_pct) / n_match
             + z * z / (4 * n_match * n_match)) ** 0.5
        ) / denom
        threat_pct_lcb = max(0.0, center - margin)

        if threat_pct_lcb < args.min_purity:
            continue

        disposition = "auto_promoted" if kind == "behavioral" else "queued"
        if disposition == "auto_promoted":
            auto_count += 1
        else:
            queued_count += 1

        sample_ips = [ip_list[i] for i in np.where(match)[0][:8]]
        rule_id = f"{disposition[:4]}_{abs(hash(itemset_str)) % 100_000_000:08d}"
        out_rows.append({
            "rule_id": rule_id,
            "itemset": items, "itemset_str": itemset_str,
            "kind": kind, "disposition": disposition,
            "ip_count": n_match,
            "threat_pct": float(threat_pct),
            "avg_risk": avg_risk,
            "sample_ips": ", ".join(sample_ips),
        })

    out_rows.sort(key=lambda r: (r["disposition"], -r["ip_count"]))
    PAT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = PAT_DIR / "candidate_rules.parquet"
    pq.write_table(pa.Table.from_pylist(out_rows, schema=RESULT_SCHEMA),
                   out_path, compression="zstd", compression_level=3)

    md_lines = [
        "# Pattern promotion report", "",
        f"Behavioral patterns auto-promoted: **{auto_count:,}**",
        f"Content patterns queued for review: **{queued_count:,}**",
        f"(skipped {skipped:,} below {args.min_ips} IPs; {unknown_tok:,} had unknown tokens)",
        "",
        "## Auto-promoted behavioral rules (top 100 by IP count)", "",
        "| rule_id | ip_count | threat_pct | avg_risk | itemset |",
        "| --- | --- | --- | --- | --- |",
    ]
    auto = [x for x in out_rows if x["disposition"] == "auto_promoted"][:100]
    for r in auto:
        md_lines.append(f"| {r['rule_id']} | {r['ip_count']:,} | "
                        f"{r['threat_pct']:.1%} | {r['avg_risk']:.1f} | "
                        f"{r['itemset_str']} |")

    md_lines.extend(["", "## Queued content rules (top 100 by IP count)", "",
                     "| rule_id | ip_count | threat_pct | avg_risk | itemset | sample_ips |",
                     "| --- | --- | --- | --- | --- | --- |"])
    queued = [x for x in out_rows if x["disposition"] == "queued"][:100]
    for r in queued:
        md_lines.append(f"| {r['rule_id']} | {r['ip_count']:,} | "
                        f"{r['threat_pct']:.1%} | {r['avg_risk']:.1f} | "
                        f"{r['itemset_str']} | {r['sample_ips']} |")

    (PAT_DIR / "candidate_rules.md").write_text("\n".join(md_lines) + "\n")
    print(f"[promote] {auto_count} auto, {queued_count} queued -> {out_path}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-ips", type=int, default=50)
    ap.add_argument("--min-purity", type=float, default=0.85)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

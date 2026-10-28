#!/usr/bin/env python3
"""
mining/mine_itemsets — FP-Growth over per-IP behavioral tuples.

For each source IP, builds a transaction set of "behavioral items":
  - port:N for each destination port hit
  - asn:N for the source ASN
  - cc:XX for the country code
  - l7:proto for each L7 protocol observed
  - ua:hash for User-Agent string hash (first 8 hex)
  - uri:tag for each matched probesigs probe tag
  - bot:family if classified into a botnet family

FP-Growth mines frequent item COMBOS that co-occur across IPs.
High-support combos = candidate behavioral signatures we hadn't
explicitly programmed for.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from collections import defaultdict
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
OUT_DIR = lib.OUTPUT_DIR / "patterns"

SCHEMA = pa.schema([
    ("itemset",     pa.list_(pa.string())),
    ("support_pct", pa.float32()),
    ("ip_count",    pa.uint32()),
    ("itemset_str", pa.string()),
    ("size",        pa.uint8()),
    # Independence-baseline statistics — multi-AI methodology review flagged
    # that raw support promotes trivial co-occurrences (e.g. every IP hits
    # port 22 + port 80). Lift = observed / expected-under-independence
    # tells us whether the combo is more frequent than chance.
    ("lift",        pa.float32()),
    ("conviction",  pa.float32()),
])



def build_transactions(con, max_ips: int = 200_000) -> list[list[str]]:
    """One transaction per IP — list of behavioral tokens."""
    print(f"[itemsets] building transactions (top {max_ips:,} IPs by packet count)...",
          file=sys.stderr)
    ip_pkts = con.execute(f"""
        SELECT src_ip, count(*) AS pkts
        FROM packets
        GROUP BY src_ip
        ORDER BY pkts DESC
        LIMIT {max_ips}
    """).fetchall()
    ips = {r[0] for r in ip_pkts}
    if not ips:
        return []

    items: dict[str, set[str]] = defaultdict(set)

    print("[itemsets] adding port tokens...", file=sys.stderr)
    rows = con.execute(f"""
        SELECT src_ip, dst_port, count(*) AS n
        FROM packets
        GROUP BY src_ip, dst_port
        HAVING count(*) >= 5
    """).fetchall()
    for ip, port, _ in rows:
        if ip in ips and port is not None:
            items[ip].add(f"port:{port}")

    print("[itemsets] adding L7 + IOC tokens...", file=sys.stderr)
    l7_rows = con.execute("""
        SELECT src_ip, l7_proto, count(*) AS n
        FROM l7_events
        GROUP BY src_ip, l7_proto
    """).fetchall()
    for ip, p, _ in l7_rows:
        if ip in ips:
            items[ip].add(f"l7:{lib.L7_NAME.get(p, 'unknown')}")

    ua_rows = con.execute(f"""
        SELECT src_ip, value
        FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['user_agent']}
        GROUP BY src_ip, value
    """).fetchall()
    for ip, ua in ua_rows:
        if ip in ips:
            h = hashlib.md5((ua or '').encode()).hexdigest()[:8]
            items[ip].add(f"ua:{h}")

    # probe tag tokens come from probesigs output (each URI we matched)
    probes_path = lib.REPORTS / "probesigs" / "probesigs.parquet"
    if probes_path.exists() and probes_path.stat().st_size > 0:
        probe_tags = con.execute(f"""
            SELECT i.src_ip, p.probe_tag
            FROM iocs i
            JOIN read_parquet('{probes_path}') p ON i.value = p.uri
            WHERE i.ioc_kind = {lib.IOC_ID['http_uri']}
            GROUP BY i.src_ip, p.probe_tag
        """).fetchall()
        for ip, tag in probe_tags:
            if ip in ips:
                items[ip].add(f"uri:{tag}")

    # botnet family tokens from botnetcls -> packets (via payload_sha256)
    bot_path = lib.REPORTS / "botnetcls" / "botnetcls.parquet"
    if bot_path.exists() and bot_path.stat().st_size > 0:
        bot_rows = con.execute(f"""
            SELECT DISTINCT p.src_ip, b.family
            FROM read_parquet('{bot_path}') b
            JOIN packets p ON p.payload_sha256 = b.payload_sha256
        """).fetchall()
        for ip, fam in bot_rows:
            if ip in ips:
                items[ip].add(f"bot:{fam}")

    # ASN + country tokens
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is not None:
        feat_path = sf.snapshot_dir(snap) / "part-0000.parquet"
        geo_rows = con.execute(f"""
            SELECT src_ip, country_iso, asn
            FROM read_parquet('{feat_path}')
        """).fetchall()
        for ip, cc, asn in geo_rows:
            if ip in ips:
                if cc:
                    items[ip].add(f"cc:{cc}")
                if asn:
                    items[ip].add(f"asn:{asn}")

    return [sorted(items[ip]) for ip in ips if items[ip]]


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    transactions = build_transactions(con, max_ips=args.max_ips)
    con.close()
    print(f"[itemsets] {len(transactions):,} non-empty transactions", file=sys.stderr)
    if not transactions:
        return 0

    from mlxtend.preprocessing import TransactionEncoder
    from mlxtend.frequent_patterns import fpgrowth

    # An item below min_support cannot be in a frequent itemset, so drop
    # those items before the dense one-hot encoding.  The FP-Growth result
    # is the same; the matrix is (IPs x frequent items) instead of
    # (IPs x every distinct port/UA/ASN), which was 49.7 GB on the
    # 1.23B-packet corpus (2026-10-25).
    min_count = args.min_support * len(transactions)
    counts: dict[str, int] = defaultdict(int)
    for t in transactions:
        for it in t:
            counts[it] += 1
    keep = {it for it, c in counts.items() if c >= min_count}
    n_items = len(counts)
    # keep the empty transactions: support = count / all transactions
    transactions = [[it for it in t if it in keep] for t in transactions]
    print(f"[itemsets] {len(keep):,} of {n_items:,} items reach min_support",
          file=sys.stderr)
    if not keep:
        return 0

    print("[itemsets] encoding transactions...", file=sys.stderr)
    te = TransactionEncoder()
    te_ary = te.fit(transactions).transform(transactions)
    import pandas as pd
    df = pd.DataFrame(te_ary, columns=te.columns_)

    min_support = args.min_support
    print(f"[itemsets] running FP-Growth (min_support={min_support}) ...", file=sys.stderr)
    freq = fpgrowth(df, min_support=min_support, use_colnames=True)
    freq = freq.sort_values("support", ascending=False)
    print(f"[itemsets] {len(freq):,} frequent itemsets found", file=sys.stderr)

    # Per-item support lookup so we can compute lift directly without
    # enumerating association rules.  mlxtend.association_rules() is
    # O(|freq| * 2^k) in itemset size and OOM-crashed at ~1M itemsets.
    # The per-item approach is O(|freq| * k).  Lift =
    #   support(I) / Π support(i)  for i in I.
    print("[itemsets] computing per-item supports...", file=sys.stderr)
    item_support: dict = {}
    for _, row in freq.iterrows():
        items = list(row["itemsets"])
        if len(items) == 1:
            item_support[items[0]] = float(row["support"])
    # Items with support below min_support don't appear in `freq` as
    # singletons, so fall back to direct column-mean for the rest.
    missing_items = set()
    for _, row in freq.iterrows():
        for it in row["itemsets"]:
            if it not in item_support:
                missing_items.add(it)
    if missing_items:
        for it in missing_items:
            item_support[it] = float(df[it].mean())

    out_rows: list[dict] = []
    n_tx = len(transactions)
    for _, row in freq.iterrows():
        items = sorted(row["itemsets"])
        if len(items) < 2:  # singletons are uninformative
            continue
        support_I = float(row["support"])
        prod = 1.0
        for it in items:
            prod *= item_support.get(it, 1.0)
        lift = support_I / prod if prod > 0 else 0.0
        if lift < args.min_lift:
            continue
        # Approximate conviction as the best 1-vs-rest split:
        # conviction(A→C) = (1 - support(C)) / (1 - confidence(A→C))
        # confidence(A→C) = support(I) / support(A)
        best_conv = 0.0
        for split_item in items:
            rest = [i for i in items if i != split_item]
            # support of "rest" is approximated by Π item_support(rest) /
            # independence — exact would require lookup of every subset,
            # which is the cost we're trying to avoid.  Use the singleton
            # split A={split_item}: support(A) = item_support(split_item).
            sup_A = item_support.get(split_item, 0.0)
            sup_C = support_I / sup_A if sup_A > 0 else 0.0  # confidence
            # actually conviction needs P(¬C). Approximate P(C) as
            # product of rest item supports (independence baseline).
            p_C = 1.0
            for r_item in rest:
                p_C *= item_support.get(r_item, 1.0)
            conf = sup_C
            denom = (1.0 - conf)
            if denom > 1e-9 and p_C < 1.0:
                conv = (1.0 - p_C) / denom
                if conv > best_conv:
                    best_conv = conv
            elif denom <= 1e-9 and p_C < 1.0:
                # conf -> 1 means infinitely strong implication
                best_conv = max(best_conv, 1e6)
        if best_conv < args.min_conviction:
            continue
        out_rows.append({
            "itemset": items,
            "support_pct": support_I,
            "ip_count": int(round(support_I * n_tx)),
            "itemset_str": " + ".join(items),
            "size": len(items),
            "lift": float(lift),
            "conviction": float(best_conv),
        })
    print(f"[itemsets] {len(out_rows):,} itemsets passed lift+conviction filter",
          file=sys.stderr)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "itemsets.parquet"
    pq.write_table(pa.Table.from_pylist(out_rows, schema=SCHEMA),
                   out_path, compression="zstd", compression_level=3)

    # Note: per-itemset rules table dropped — the previous mlxtend
    # `association_rules` path OOM-crashed at ~1M frequent itemsets.
    # Lift/conviction are now attached directly to each itemset row,
    # which is the gating signal we actually consume downstream.

    md_lines = ["# Mined itemsets", "",
                f"{len(out_rows):,} multi-item frequent combos "
                f"(min support {min_support:.0%} = "
                f"{int(min_support * len(transactions))} IPs, "
                f"min lift {args.min_lift}, "
                f"min conviction {args.min_conviction}).",
                "", "## Top 50 by lift", "",
                "_Lift = observed support / expected-under-independence. "
                "Lift >> 1 means the items co-occur far more than chance. "
                "Conviction measures implication strength; higher = "
                "antecedent more strongly implies consequent._",
                "",
                "| size | ip_count | support | lift | conviction | itemset |",
                "| --- | --- | --- | --- | --- | --- |"]
    out_rows.sort(key=lambda r: r["lift"], reverse=True)
    for r in out_rows[:50]:
        md_lines.append(
            f"| {r['size']} | {r['ip_count']:,} | "
            f"{r['support_pct']:.1%} | {r['lift']:.2f} | "
            f"{r['conviction']:.2f} | {r['itemset_str']} |"
        )
    (OUT_DIR / "itemsets.md").write_text("\n".join(md_lines) + "\n")
    print(f"[itemsets] wrote {out_path} "
          f"({len(out_rows):,} itemsets)", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-ips", type=int, default=200_000,
                    help="Cap the transaction set at the top N IPs by packet count")
    ap.add_argument("--min-support", type=float, default=0.005,
                    help="Minimum support fraction for FP-Growth")
    ap.add_argument("--min-lift", type=float, default=2.0,
                    help="Minimum lift to keep an itemset/rule "
                         "(default 2.0 = co-occurs at least twice as often "
                         "as independence baseline)")
    ap.add_argument("--min-conviction", type=float, default=1.5,
                    help="Minimum conviction to keep an itemset/rule "
                         "(default 1.5; conviction=1.0 is independence)")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
mining/mine_sequences — sequential pattern mining over attack chains.

Reads the per-IP attack chains produced by attack_chains.py and mines
common ordered subsequences. Each chain is a string over {R,P,X,C,D,B}
(see attack_chains.py). We mine:

  1. Contiguous n-grams of length 2-4 (most common "next-step" patterns)
  2. Non-contiguous subsequences via PrefixSpan up to length 4

The output identifies common attacker playbooks ("most attackers go
R -> X -> D within 2 days") and gives baseline counts you can compare
against to detect novel sequences.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib

CHAINS_PATH = lib.OUTPUT_DIR / "patterns" / "attack_chains" / "per_ip.parquet"
OUT_DIR = lib.OUTPUT_DIR / "patterns" / "sequences"

NGRAM_SCHEMA = pa.schema([
    ("ngram",       pa.string()),
    ("length",      pa.uint8()),
    ("ip_count",    pa.uint32()),
    ("support_pct", pa.float32()),
])

SUBSEQ_SCHEMA = pa.schema([
    ("subseq",      pa.string()),
    ("length",      pa.uint8()),
    ("ip_count",    pa.uint32()),
    ("support_pct", pa.float32()),
])


def mine_ngrams(chains: list[str], max_n: int = 4, min_support: int = 20) -> list[tuple[str, int, int]]:
    """Return (ngram, length, count) tuples for contiguous n-grams."""
    counts: Counter = Counter()
    for c in chains:
        for n in range(2, max_n + 1):
            for i in range(len(c) - n + 1):
                counts[c[i:i+n]] += 1
    return [(g, len(g), n) for g, n in counts.items() if n >= min_support]


def mine_subseqs(chains: list[str], max_len: int = 4, min_support: int = 20) -> list[tuple[str, int, int]]:
    """Mine non-contiguous subsequences via enumeration on the small alphabet.

    Each chain has length <= 6 (the 6 stages), so combinations are bounded.
    """
    counts: Counter = Counter()
    for c in chains:
        seen = set()
        for k in range(2, min(max_len, len(c)) + 1):
            for idxs in combinations(range(len(c)), k):
                sub = "".join(c[i] for i in idxs)
                if sub in seen:
                    continue
                seen.add(sub)
                counts[sub] += 1
    return [(s, len(s), n) for s, n in counts.items() if n >= min_support]


def run(args: argparse.Namespace) -> int:
    if not CHAINS_PATH.exists():
        print("[sequences] no attack chains - run longitudinal/attack_chains.py first",
              file=sys.stderr)
        return 2

    con = lib.duck()
    rows = con.execute(f"SELECT chain FROM read_parquet('{CHAINS_PATH}')").fetchall()
    con.close()
    chains = [r[0] for r in rows if r[0]]
    n = len(chains)
    print(f"[sequences] loaded {n:,} attacker chain strings", file=sys.stderr)
    if not chains:
        return 0

    min_supp = max(args.min_support, int(args.min_support_pct * n))
    print(f"[sequences] min support: {min_supp:,} IPs", file=sys.stderr)

    print("[sequences] mining contiguous n-grams...", file=sys.stderr)
    ngrams = mine_ngrams(chains, max_n=args.max_n, min_support=min_supp)
    ngrams.sort(key=lambda x: x[2], reverse=True)

    print("[sequences] mining non-contiguous subsequences...", file=sys.stderr)
    subs = mine_subseqs(chains, max_len=args.max_n, min_support=min_supp)
    subs.sort(key=lambda x: x[2], reverse=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(
        [{"ngram": g, "length": l, "ip_count": c,
          "support_pct": c / n} for g, l, c in ngrams],
        schema=NGRAM_SCHEMA),
        OUT_DIR / "ngrams.parquet",
        compression="zstd", compression_level=3)
    pq.write_table(pa.Table.from_pylist(
        [{"subseq": s, "length": l, "ip_count": c,
          "support_pct": c / n} for s, l, c in subs],
        schema=SUBSEQ_SCHEMA),
        OUT_DIR / "subsequences.parquet",
        compression="zstd", compression_level=3)

    md_lines = ["# Sequential pattern mining", "",
                f"Mined over **{n:,}** attacker chain strings.",
                f"Min support: {min_supp:,} IPs.", "",
                "## Top 30 contiguous n-grams (consecutive stage transitions)",
                "",
                "| ngram | length | ip_count | support |",
                "| --- | --- | --- | --- |"]
    for g, l, c in ngrams[:30]:
        md_lines.append(f"| {g} | {l} | {c:,} | {c/n:.1%} |")

    md_lines.extend(["",
                     "## Top 30 non-contiguous subsequences (interleaved patterns)",
                     "",
                     "| subseq | length | ip_count | support |",
                     "| --- | --- | --- | --- |"])
    for s, l, c in subs[:30]:
        md_lines.append(f"| {s} | {l} | {c:,} | {c/n:.1%} |")
    (OUT_DIR / "sequences.md").write_text("\n".join(md_lines) + "\n")

    print(f"[sequences] {len(ngrams):,} ngrams + {len(subs):,} subseqs -> {OUT_DIR}",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-n", type=int, default=4)
    ap.add_argument("--min-support", type=int, default=20)
    ap.add_argument("--min-support-pct", type=float, default=0.001)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

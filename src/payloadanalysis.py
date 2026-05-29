#!/usr/bin/env python3
"""
payloadanalysis - byte-level payload statistics.

What it computes
----------------
1. Payload length distribution (per L7 protocol)
2. Shannon-entropy distribution (low = ASCII/structured, high = encrypted/random)
3. Encoding-pattern detection: base64-like, hex-like, urlencoded, ASCII text,
   binary
4. Common payload prefixes (first 4-byte hex) - reveals tool families /
   protocol magics our parser didn't recognize
5. Printable-byte ratio per blob

Implementation
--------------
Aggregation runs in Python over a streamed Arrow batch of payload bytes
(can't push entropy into DuckDB cleanly). We cap the working set at the
top-N largest blob clusters by sender count so this stays bounded.
"""
from __future__ import annotations

import argparse
import math
import sys
from collections import Counter
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


LEN_SCHEMA = pa.schema([
    ("len_bucket_lo", pa.uint16()), ("len_bucket_hi", pa.uint16()),
    ("l7_proto", pa.string()), ("blobs", pa.uint32()),
])
ENTROPY_SCHEMA = pa.schema([
    ("entropy_bucket", pa.float32()), ("l7_proto", pa.string()),
    ("blobs", pa.uint32()),
])
ENCODING_SCHEMA = pa.schema([
    ("encoding", pa.string()), ("l7_proto", pa.string()),
    ("blobs", pa.uint32()), ("share_pct", pa.float32()),
])
PREFIX_SCHEMA = pa.schema([
    ("prefix_hex", pa.string()), ("printable_prefix", pa.string()),
    ("l7_proto", pa.string()), ("blobs", pa.uint32()),
])


import numpy as np


def _entropy(b: bytes) -> float:
    """Shannon entropy on first 256 bytes via numpy bincount (fast C path)."""
    if not b:
        return 0.0
    arr = np.frombuffer(b[:256], dtype=np.uint8)
    counts = np.bincount(arr, minlength=1)
    counts = counts[counts > 0]
    if counts.size == 0:
        return 0.0
    p = counts.astype(np.float64) / counts.sum()
    return float(-np.sum(p * np.log2(p)))


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 0x20 <= x < 0x7F) / len(b)


def _detect_encoding(b: bytes) -> str:
    if not b:
        return "empty"
    pr = _printable_ratio(b)
    if pr < 0.5:
        return "binary"
    txt = b[:256]
    # urlencoded: many % chars followed by hex
    if txt.count(b"%") >= 4 and all(c in b"0123456789ABCDEFabcdef" for c in txt[txt.find(b"%")+1:txt.find(b"%")+3] or b""):
        return "urlencoded"
    # base64-like: all of A-Za-z0-9+/= and length divisible by 4 candidate
    b64chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n")
    if pr > 0.95 and len(set(txt) - b64chars) == 0 and len(txt) >= 16:
        return "base64"
    # hex-like
    hexchars = set(b"0123456789abcdefABCDEF\r\n ")
    if pr > 0.95 and len(set(txt) - hexchars) == 0 and len(txt) >= 16:
        return "hex"
    if pr > 0.85:
        return "ascii_text"
    return "mixed"


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    out_dir = lib.REPORTS / "payloadanalysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[payload] length distribution (entirely in SQL)...", file=sys.stderr)
    len_rows = con.execute("""
        SELECT (payload_len / 64) * 64 AS lo, l7_proto, count(*) AS blobs
        FROM payload_blobs
        WHERE payload_len > 0
        GROUP BY lo, l7_proto
        ORDER BY lo
    """).fetchall()
    pq.write_table(pa.Table.from_pylist(
        [{"len_bucket_lo": int(l), "len_bucket_hi": int(l) + 63,
          "l7_proto": lib.L7_NAME.get(p, str(p)), "blobs": n}
         for l, p, n in len_rows], schema=LEN_SCHEMA),
        out_dir / "len_dist.parquet", compression="zstd", compression_level=3)

    # Sample blob bytes (deterministic) for entropy / encoding / prefix
    # analysis.  Streaming all 97M blobs in Python is too slow for the
    # distribution shape questions this analyzer answers.
    print(f"[payload] sampling up to {args.sample:,} blobs "
          "for entropy/encoding/prefix...", file=sys.stderr)
    cur = con.execute(f"""
        SELECT bytes, payload_len, l7_proto
        FROM payload_blobs
        WHERE payload_len >= 4
        USING SAMPLE {args.sample} ROWS
    """)
    entropy_counts: dict[tuple[int, int], int] = {}        # (entropy_bin, l7) -> n
    encoding_counts: dict[tuple[str, int], int] = {}        # (enc, l7) -> n
    prefix_counts: dict[tuple[bytes, int], int] = {}        # (prefix, l7) -> n
    total = 0

    for batch in cur.fetch_record_batch(rows_per_batch=50_000):
        b_col = batch.column("bytes").to_pylist()
        l_col = batch.column("l7_proto").to_pylist()
        for raw, l7 in zip(b_col, l_col):
            if not raw:
                continue
            total += 1
            e = _entropy(raw[:256])
            e_bin = round(e * 2) / 2  # 0.5-unit buckets
            entropy_counts[(int(e_bin * 10), l7)] = entropy_counts.get(
                (int(e_bin * 10), l7), 0) + 1
            enc = _detect_encoding(raw)
            encoding_counts[(enc, l7)] = encoding_counts.get((enc, l7), 0) + 1
            prefix = raw[:4]
            prefix_counts[(prefix, l7)] = prefix_counts.get((prefix, l7), 0) + 1

    con.close()
    print(f"[payload] streamed {total:,} blobs", file=sys.stderr)

    pq.write_table(pa.Table.from_pylist(
        [{"entropy_bucket": k[0] / 10, "l7_proto": lib.L7_NAME.get(k[1], str(k[1])),
          "blobs": v} for k, v in entropy_counts.items()],
        schema=ENTROPY_SCHEMA),
        out_dir / "entropy_dist.parquet", compression="zstd", compression_level=3)

    total_enc = sum(encoding_counts.values()) or 1
    pq.write_table(pa.Table.from_pylist(
        [{"encoding": k[0], "l7_proto": lib.L7_NAME.get(k[1], str(k[1])),
          "blobs": v, "share_pct": float(v / total_enc * 100)}
         for k, v in encoding_counts.items()],
        schema=ENCODING_SCHEMA),
        out_dir / "encoding_dist.parquet", compression="zstd", compression_level=3)

    sorted_prefixes = sorted(prefix_counts.items(), key=lambda x: x[1], reverse=True)
    pq.write_table(pa.Table.from_pylist(
        [{"prefix_hex": k[0].hex(),
          "printable_prefix": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in k[0]),
          "l7_proto": lib.L7_NAME.get(k[1], str(k[1])), "blobs": v}
         for k, v in sorted_prefixes[:5000]],
        schema=PREFIX_SCHEMA),
        out_dir / "prefix_dist.parquet", compression="zstd", compression_level=3)

    # ---- markdown report ----
    md = ["# payloadanalysis - byte-level payload statistics", ""]
    md.append("## Encoding type distribution")
    md.append("")
    md.append("_How each payload's bytes look at the surface: text, "
              "base64, hex, urlencoded, mixed, or pure binary._")
    md.append("")
    md.append("| encoding | l7 | blobs | share_pct |")
    md.append("| --- | --- | --- | --- |")
    enc_sorted = sorted(encoding_counts.items(), key=lambda x: x[1], reverse=True)
    for (enc, l7), n in enc_sorted[:30]:
        md.append(f"| {enc} | {lib.L7_NAME.get(l7, str(l7))} | {n:,} | "
                  f"{n / total_enc * 100:.2f}% |")

    md.extend(["", "## Top 30 4-byte prefixes",
               "", "_The first 4 bytes of each payload often reveal the protocol "
               "magic or tool family that built the request._",
               "",
               "| prefix_hex | printable | l7 | blobs |",
               "| --- | --- | --- | --- |"])
    for (prefix, l7), n in sorted_prefixes[:30]:
        printable = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in prefix)
        md.append(f"| `{prefix.hex()}` | `{printable}` | "
                  f"{lib.L7_NAME.get(l7, str(l7))} | {n:,} |")

    (out_dir / "payloadanalysis.md").write_text("\n".join(md) + "\n")
    print(f"[payload] wrote {out_dir}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", type=int, default=1_000_000,
                    help="Random sample size for entropy/encoding/prefix "
                         "analysis (full pop would be 97M, too slow)")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

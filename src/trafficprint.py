#!/usr/bin/env python3
"""
trafficprint — fast payload clustering by prefix signature.

Two-pass aggregation:
  pass 1: GROUP BY (md5-of-first-32-bytes, len_bucket, l7_proto)
          aggregating only scalars (count, avg_len, sample_sha256).
  pass 2: for the top N surviving clusters, look up one representative
          payload's bytes and strings.

This keeps DuckDB aggregator state small (no per-group BLOB samples).
"""
from __future__ import annotations

import argparse
import sys

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("cluster_id",      pa.uint32()),
    ("signature_hash",  pa.string()),
    ("blob_count",      pa.uint64()),
    ("avg_payload_len", pa.float32()),
    ("len_bucket",      pa.uint16()),
    ("l7_proto",        pa.string()),
    ("sample_sha256",   pa.string()),
    ("sample_strings",  pa.string()),
    ("sample_prefix",   pa.string()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    # Make DuckDB spill aggregations to disk when memory pressure builds.
    con.execute("SET threads=4")
    con.execute("SET preserve_insertion_order=false")

    max_clusters = args.limit or 50_000
    print("[trafficprint] pass 1: grouping by prefix signature (scalars only)...",
          file=sys.stderr)
    rows = con.execute(f"""
        SELECT
            md5(bytes[1:32])                       AS sig_hash,
            (payload_len / 64) * 64                AS len_bucket,
            l7_proto,
            count(*)                               AS blob_count,
            avg(payload_len)                       AS avg_len,
            arg_max(payload_sha256, payload_len)   AS sample_sha
        FROM payload_blobs
        WHERE payload_len >= 8
        GROUP BY sig_hash, len_bucket, l7_proto
        HAVING count(*) >= 2
        ORDER BY blob_count DESC
        LIMIT {max_clusters}
    """).fetchall()
    print(f"[trafficprint] {len(rows):,} multi-member clusters", file=sys.stderr)

    # Pass 2: fetch one sample blob (bytes + strings) per surviving cluster.
    print("[trafficprint] pass 2: fetching sample bytes for top clusters...",
          file=sys.stderr)
    sample_shas = [r[5] for r in rows if r[5] is not None]
    bytes_map: dict[bytes, tuple] = {}
    if sample_shas:
        con.execute("CREATE TEMP TABLE tp_sha (sha BLOB)")
        for sha in sample_shas:
            con.execute("INSERT INTO tp_sha VALUES (?)", [sha])
        sample_rows = con.execute("""
            SELECT b.payload_sha256, b.bytes, b.strings
            FROM payload_blobs b
            JOIN tp_sha t ON b.payload_sha256 = t.sha
        """).fetchall()
        for sha, payload_bytes, strings in sample_rows:
            bytes_map[sha] = (payload_bytes, strings)
    con.close()

    results: list[dict] = []
    for cid, r in enumerate(rows):
        sig_hash, len_bucket, l7, count, avg_len, sample_sha = r
        sample_bytes, sample_strings = bytes_map.get(sample_sha, (b"", []))
        prefix = bytes(b if 0x20 <= b < 0x7F else 0x2E for b in (sample_bytes or b"")[:64])
        results.append({
            "cluster_id": cid,
            "signature_hash": sig_hash.hex() if isinstance(sig_hash, bytes) else str(sig_hash),
            "blob_count": int(count),
            "avg_payload_len": float(avg_len or 0),
            "len_bucket": int(len_bucket or 0),
            "l7_proto": lib.L7_NAME.get(l7, "unknown"),
            "sample_sha256": sample_sha.hex()[:16] if sample_sha else "",
            "sample_strings": " | ".join((sample_strings or [])[:5]),
            "sample_prefix": prefix.decode("ascii", errors="replace")[:120],
        })

    top_n = min(40, len(results))
    md = f"""## Summary

- **{len(results):,}** multi-member clusters (top {max_clusters:,} by size)
- Grouped by md5(first 32 bytes) × length-bucket × L7 protocol

## Top {top_n} clusters by blob count

"""
    md += lib.markdown_table(results[:top_n],
        columns=["cluster_id", "blob_count", "avg_payload_len", "len_bucket",
                 "l7_proto", "sample_prefix"])

    return lib.Report(name="trafficprint", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[trafficprint] wrote {paths['parquet']}")
    print(f"[trafficprint] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

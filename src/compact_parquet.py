#!/usr/bin/env python3
"""
compact_parquet — coalesce the parser's many tiny per-flush part files into a
few ``rows_per_part``-sized files, in place, WITHOUT re-parsing.

The parser historically rolled a brand-new file on every 5,000-row flush, so a
table/day could hold hundreds of ~150 KB files (~223k files for packets).  This
rewrites each ``dt=`` partition as a handful of ~``rows_per_part``-row files,
preserving rows, schema and partitioning exactly.

Safe by construction:
  * Per partition, coalesced files are written to a temp sibling dir, the row
    count is verified against the originals, and only then are the originals
    swapped out -- a crash leaves the originals untouched.
  * Idempotent: partitions already at/under the target file count are skipped,
    so it's cheap to re-run (and a no-op on output from the fixed parser).

Row CONTENT is preserved; physical row ORDER within a partition may change
(parquet data-lake semantics -- analyzers filter/aggregate, they don't rely on
file row order).

Usage:
  python src/compact_parquet.py                 # all tables, 500k rows/file
  python src/compact_parquet.py --dry-run       # report only, touch nothing
  python src/compact_parquet.py --tables packets --rows-per-part 250000
"""
from __future__ import annotations

import argparse
import math
import shutil
import sys
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib

DEFAULT_TABLES = ["packets", "payload_blobs", "l7_events", "iocs"]
# Streaming scan batch (rows held in RAM at once).  payload_blobs carries the
# raw payload bytes, so it uses a much smaller batch to cap memory (mirrors the
# parser's BATCH_ROWS_BLOBS); the others are small fixed-width columns.
SCAN_BATCH = {"payload_blobs": 2_000}
SCAN_BATCH_DEFAULT = 64_000


def _rows(files: list[Path]) -> int:
    return sum(pq.ParquetFile(f).metadata.num_rows for f in files)


def compact_dir(d: Path, rows_per_part: int, dry_run: bool,
                scan_batch: int = SCAN_BATCH_DEFAULT) -> tuple[int, int]:
    """Coalesce one ``dt=`` partition.  Returns (src_files, dst_files);
    dst==src means it was already coalesced and left untouched."""
    files = sorted(d.glob("part-*.parquet"))
    if not files:
        return (0, 0)
    src_rows = _rows(files)
    target = max(1, math.ceil(src_rows / rows_per_part))
    if len(files) <= target:
        return (len(files), len(files))          # already coalesced
    if dry_run:
        return (len(files), target)

    schema = ds.dataset(files, format="parquet").schema
    tmp = d.with_name(d.name + ".cmpct.tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)

    part = cur = 0
    writer: pq.ParquetWriter | None = None
    scanner = ds.dataset(files, format="parquet").scanner(batch_size=scan_batch)
    for batch in scanner.to_batches():
        if batch.num_rows == 0:
            continue
        if writer is None:
            writer = pq.ParquetWriter(tmp / f"part-{part:04d}.parquet", schema,
                                      compression="zstd", compression_level=3)
            cur = 0
        writer.write_table(pa.Table.from_batches([batch]))
        cur += batch.num_rows
        if cur >= rows_per_part:
            writer.close()
            writer = None
            part += 1
    if writer is not None:
        writer.close()

    new_files = sorted(tmp.glob("part-*.parquet"))
    new_rows = _rows(new_files)
    if new_rows != src_rows:                     # safety: never lose data
        shutil.rmtree(tmp)
        raise RuntimeError(
            f"row mismatch in {d}: {src_rows:,} -> {new_rows:,}; "
            f"aborted, originals untouched")
    for f in files:                              # swap originals out
        f.unlink()
    for f in new_files:
        f.rename(d / f.name)
    shutil.rmtree(tmp)
    return (len(files), len(new_files))


def run(args: argparse.Namespace) -> int:
    rpp = max(1, args.rows_per_part)
    grand_src = grand_dst = 0
    for table in args.tables:
        base = lib.PARQUET / table
        if not base.exists():
            print(f"[compact] {table}: not present, skipping", file=sys.stderr)
            continue
        dt_dirs = sorted(p for p in base.glob("dt=*") if p.is_dir())
        sb = SCAN_BATCH.get(table, SCAN_BATCH_DEFAULT)
        t0 = time.time()
        tsrc = tdst = changed = 0
        for d in dt_dirs:
            s, dn = compact_dir(d, rpp, args.dry_run, sb)
            tsrc += s
            tdst += dn
            if dn < s:
                changed += 1
        grand_src += tsrc
        grand_dst += tdst
        verb = "would coalesce" if args.dry_run else "coalesced"
        print(f"[compact] {table}: {len(dt_dirs):,} partitions; {verb} "
              f"{tsrc:,} -> {tdst:,} files ({changed} partitions changed) "
              f"in {time.time() - t0:.1f}s", file=sys.stderr)
    print(f"[compact] TOTAL: {grand_src:,} -> {grand_dst:,} files"
          f"{' (dry run)' if args.dry_run else ''}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tables", nargs="*", default=DEFAULT_TABLES,
                    help=f"tables to compact (default: {DEFAULT_TABLES})")
    ap.add_argument("--rows-per-part", type=int, default=500_000,
                    help="target rows per coalesced file (default 500k)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change; modify nothing")
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())

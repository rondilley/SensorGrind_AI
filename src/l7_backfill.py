#!/usr/bin/env python3
"""
l7_backfill — apply the current parser l7 classifier to the stored parquet.

The parser labels each payload (``detect_l7``) when it parses the log; the
label goes into packets.l7_proto, payload_blobs.l7_proto, and an l7_events row
(with ``extract_l7_fields``) for each packet whose payload got fields.  When the
classifier learns a new protocol, the stored tables keep the old label until a
full re-parse.  This tool changes only what the new classifier changes:

  1. targets: stored payload_blobs whose current label differs from
     ``parser.detect_l7(bytes)`` (only payloads that a classifier rule can
     newly match are read: the BitTorrent-layout handshakes)
  2. l7_events rows for every packet that carries a target payload, in the raw
     layout (l7_events/dt=D/part-l7backfill-<labels>.parquet) and the clustered
     layout (l7_events_clustered/bkt=K/l7backfill-<labels>.parquet, asn/cidr/bkt
     from the
     packet's packets_clustered row)
  3. l7_proto in every packets, packets_clustered and payload_blobs file that
     holds a target payload, rewritten one row group at a time with the same
     schema; the original file moves to the backup folder first

payload_blobs is rewritten last, because it defines the targets: after a full
run a second run finds nothing, and after a stopped run a second run writes the
same l7_events files again (same names) and finishes the rest.

    python src/l7_backfill.py              # dry run: counts only
    python src/l7_backfill.py --apply      # write; originals -> backup folder
    python src/l7_backfill.py --apply --no-backup

The freshness cache sees the new file times, so the next evolve run reruns the
stages that read these tables.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import shutil
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib
import parser as sgparser

BACKUP_ROOT = lib.OUTPUT_DIR / ".l7_backfill_backup"
L7_RAW_NAME = "part-l7backfill.parquet"
L7_CLUSTERED_NAME = "l7backfill.parquet"


def _named(base: str, con) -> str:
    """The l7_events file name of this run: the base name plus the new labels
    (part-l7backfill-levin.parquet).  A backfill for a different protocol
    thus never replaces an earlier one's rows on the same day; the first
    (BitTorrent) backfill keeps the plain base name."""
    labels = sorted({lib.L7_NAME.get(int(l7), str(l7)) for (l7,) in con.execute(
        "SELECT DISTINCT new_l7 FROM targets").fetchall()})
    stem, ext = base.rsplit(".", 1)
    return f"{stem}-{'-'.join(labels)}.{ext}"

# Payloads a classifier rule can newly match: the BitTorrent handshake layout
# (pstrlen 19, 68 bytes), the DL protocol string at any length, and the Levin
# (Monero P2P) signature.
_DL_HEX = sgparser._BITTORRENT_DL_PREFIX.hex().upper()
_LEVIN_HEX = sgparser._LEVIN_SIGNATURE.hex().upper()
CANDIDATE_SQL = (f"(payload_len = 68 AND starts_with(hex(bytes), '13')) "
                 f"OR starts_with(hex(bytes), '{_DL_HEX}') "
                 f"OR starts_with(hex(bytes), '{_LEVIN_HEX}')")


def find_targets(con) -> pa.Table:
    """sha256 -> new l7 and fields_json, for blobs whose label changes."""
    rows = con.execute(f"""
        SELECT DISTINCT payload_sha256, l7_proto, bytes FROM payload_blobs
        WHERE {CANDIDATE_SQL}
    """).fetchall()
    sha, new, fields = [], [], []
    for h, old, b in rows:
        b = bytes(b)
        l7 = sgparser.detect_l7(b, None, None)
        if l7 == old:
            continue
        f = sgparser.extract_l7_fields(l7, b)
        sha.append(bytes(h))
        new.append(l7)
        fields.append(sgparser._json_dump(f) if f else None)
    return pa.table({"payload_sha256": pa.array(sha, pa.binary()),
                     "new_l7": pa.array(new, pa.uint8()),
                     "fields_json": pa.array(fields, pa.string())})


def files_with_targets(con, glob: str) -> list[str]:
    return [r[0] for r in con.execute(f"""
        SELECT DISTINCT filename
        FROM read_parquet('{glob}', filename = true, hive_partitioning = false)
        WHERE payload_sha256 IN (SELECT payload_sha256 FROM targets)
        ORDER BY 1
    """).fetchall()]


def rewrite_file(path: str, shas: list[bytes], new_l7: list[int],
                 backup: str | None) -> tuple[str, int]:
    """Set l7_proto for the target payloads in one file; same schema and
    row-group structure.  Returns (path, rows changed)."""
    src = Path(path)
    lookup = pa.array(shas, pa.binary())
    values = pa.array(new_l7, pa.uint8())
    pf = pq.ParquetFile(src)
    schema = pf.schema_arrow
    tmp = src.with_name(src.name + ".l7tmp")
    changed = 0
    with pq.ParquetWriter(tmp, schema, compression="zstd",
                          compression_level=3) as w:
        for i in range(pf.num_row_groups):
            t = pf.read_row_group(i)
            sha = t.column("payload_sha256").cast(pa.binary())
            idx = pc.index_in(sha, value_set=lookup)
            mask = pc.is_valid(idx)
            n = pc.sum(mask).as_py() or 0
            if n:
                col = t.schema.get_field_index("l7_proto")
                new = pc.if_else(mask, pc.take(values, idx), t.column(col))
                t = t.set_column(col, t.schema.field(col),
                                 new.cast(t.schema.field(col).type))
                changed += n
            w.write_table(t)
    if backup:
        dst = Path(backup) / src.relative_to(lib.PARQUET)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(src, dst)
    os.replace(tmp, src)
    return path, changed


def write_l7_events(con, apply: bool) -> tuple[int, int]:
    """The l7_events rows the parser would have written for target packets."""
    n_raw = con.execute("""
        SELECT count(*) FROM packets p JOIN targets t USING (payload_sha256)
        WHERE t.fields_json IS NOT NULL
    """).fetchone()[0]
    n_cl = 0
    if lib.has_clustered(lib.PACKETS_CLUSTERED):
        n_cl = con.execute(f"""
            SELECT count(*) FROM read_parquet('{lib.PACKETS_CLUSTERED_GLOB}') p
            JOIN targets t ON p.payload_sha256 = t.payload_sha256
            WHERE t.fields_json IS NOT NULL
        """).fetchone()[0]
    if not apply:
        return n_raw, n_cl
    days = [r[0] for r in con.execute("""
        SELECT DISTINCT p.dt FROM packets p JOIN targets t USING (payload_sha256)
        WHERE t.fields_json IS NOT NULL ORDER BY 1
    """).fetchall()]
    for day in days:
        tbl = con.execute(f"""
            SELECT p.ts, p.src_ip, p.dst_port, t.new_l7 AS l7_proto,
                   p.payload_sha256, t.fields_json
            FROM packets p JOIN targets t USING (payload_sha256)
            WHERE p.dt = DATE '{day}' AND t.fields_json IS NOT NULL
            ORDER BY p.ts
        """).to_arrow_table().cast(sgparser.L7_SCHEMA)
        out = lib.PARQUET / "l7_events" / f"dt={day}" / _named(L7_RAW_NAME, con)
        out.parent.mkdir(parents=True, exist_ok=True)
        pq.write_table(tbl, out, compression="zstd", compression_level=3)
    if n_cl:
        sample = next(lib.L7_CLUSTERED.glob("bkt=*/*.parquet"))
        cl_schema = pq.read_schema(sample)
        for (bkt,) in con.execute(f"""
            SELECT DISTINCT regexp_extract(p.filename, 'bkt=([0-9]+)', 1)
            FROM read_parquet('{lib.PACKETS_CLUSTERED_GLOB}', filename = true,
                              hive_partitioning = false) p
            JOIN targets t ON p.payload_sha256 = t.payload_sha256
            WHERE t.fields_json IS NOT NULL
        """).fetchall():
            tbl = con.execute(f"""
                SELECT p.ts, p.src_ip, p.dst_port, t.new_l7 AS l7_proto,
                       p.payload_sha256, t.fields_json, p.dt, p.asn, p.cidr
                FROM read_parquet('{lib.PACKETS_CLUSTERED}/bkt={bkt}/*.parquet',
                                  hive_partitioning = false) p
                JOIN targets t ON p.payload_sha256 = t.payload_sha256
                WHERE t.fields_json IS NOT NULL
                ORDER BY p.asn, p.cidr, p.src_ip, p.ts
            """).to_arrow_table().select(cl_schema.names).cast(cl_schema)
            out = lib.L7_CLUSTERED / f"bkt={bkt}" / _named(L7_CLUSTERED_NAME, con)
            out.parent.mkdir(parents=True, exist_ok=True)
            pq.write_table(tbl, out, compression="zstd", compression_level=3)
    return n_raw, n_cl


def run(args: argparse.Namespace) -> int:
    t0 = time.time()
    con = lib.duck()
    lib.register_views(con)
    targets = find_targets(con)
    con.register("targets_arrow", targets)
    con.execute("CREATE TEMP TABLE targets AS SELECT * FROM targets_arrow")
    print(f"[l7_backfill] {targets.num_rows:,} payloads change label "
          f"({time.time() - t0:.0f}s)", file=sys.stderr)
    if targets.num_rows == 0:
        print("[l7_backfill] nothing to do", file=sys.stderr)
        return 0
    for (l7, n) in con.execute(
            "SELECT new_l7, count(*) FROM targets GROUP BY 1 ORDER BY 2 DESC").fetchall():
        print(f"[l7_backfill]   -> {lib.L7_NAME.get(int(l7), l7)}: {n:,}",
              file=sys.stderr)

    datasets = [("packets", lib.PACKETS_GLOB)]
    if lib.has_clustered(lib.PACKETS_CLUSTERED):
        datasets.append(("packets_clustered", lib.PACKETS_CLUSTERED_GLOB))
    datasets.append(("payload_blobs", lib.BLOBS_GLOB))     # last: defines targets
    files = {name: files_with_targets(con, glob) for name, glob in datasets}
    for name, fl in files.items():
        size = sum(Path(f).stat().st_size for f in fl)
        print(f"[l7_backfill] {name}: {len(fl):,} files to rewrite "
              f"({size / 2**30:.1f} GiB)", file=sys.stderr)

    n_raw, n_cl = write_l7_events(con, apply=False)
    print(f"[l7_backfill] l7_events rows to add: {n_raw:,} raw, "
          f"{n_cl:,} clustered", file=sys.stderr)
    if not args.apply:
        print("[l7_backfill] dry run; pass --apply to write", file=sys.stderr)
        return 0

    write_l7_events(con, apply=True)
    con.close()
    print(f"[l7_backfill] wrote l7_events rows ({time.time() - t0:.0f}s)",
          file=sys.stderr)

    backup = None
    if not args.no_backup:
        backup = BACKUP_ROOT / _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
        backup.mkdir(parents=True, exist_ok=True)
        print(f"[l7_backfill] originals -> {backup}", file=sys.stderr)
    shas = targets.column("payload_sha256").to_pylist()
    new = targets.column("new_l7").to_pylist()
    for name, _ in datasets:
        changed = 0
        with ProcessPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(rewrite_file, f, shas, new,
                              str(backup) if backup else None)
                    for f in files[name]]
            for k, fu in enumerate(futs, 1):
                changed += fu.result()[1]
                if k % 100 == 0 or k == len(futs):
                    print(f"[l7_backfill]   {name}: {k}/{len(futs)} files",
                          file=sys.stderr, flush=True)
        print(f"[l7_backfill] {name}: {changed:,} rows relabelled "
              f"({time.time() - t0:.0f}s)", file=sys.stderr)
    print("[l7_backfill] done", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="write the changes (default: dry run)")
    ap.add_argument("--no-backup", action="store_true",
                    help="do not keep the original files")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 4))
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())

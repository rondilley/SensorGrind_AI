#!/usr/bin/env python3
"""
Consolidate raw honeypot syslog .gz files into a single sorted, deduplicated
event timeline.

Pipeline
--------
1. Parallel extraction: for each input .gz file, `zcat` -> filter `sensor:` lines
   -> parse `PacketTime:` -> emit `<ISO_UTC>\\t<raw_line>` to a per-file gzipped
   intermediate. Records per-file first/last timestamps for a manifest.
2. Global merge: `LC_ALL=C sort -u` across all intermediates, piped into gzip,
   producing one consolidated `merged.log.gz`. Because each line starts with an
   ISO 8601 UTC timestamp, lexicographic sort == chronological sort.

Scope
-----
Only lines containing ``sensor: PacketTime:<YYYY-MM-DD HH:MM:SS.ffffff>`` are
kept (honeypot data). Fortinet firewall and newsyslog rotation lines are
dropped. PacketTime is treated as UTC.

Output
------
~/temp/sensor_logs/consolidated/
    merged.log.gz       # <iso_utc>\\t<raw_line> per line, gzipped
    manifest.tsv        # per-input-file: path, sensor_lines, ts_first, ts_last
"""

import argparse
import gzip
import multiprocessing as mp
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

PACKET_TIME_RE = re.compile(
    r"PacketTime:(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+)"
)


def extract_one(args):
    """Worker: read one .gz, write per-file gzipped TSV, return manifest row."""
    src_path, out_path = args
    src = Path(src_path)
    out = Path(out_path)
    first_ts = None
    last_ts = None
    count = 0

    # zcat is faster than Python's gzip for sequential decompression of large
    # files. We pipe it to Python via subprocess for streaming.
    proc = subprocess.Popen(
        ["zcat", str(src)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=1 << 20,
    )
    try:
        with gzip.open(out, "wt", encoding="utf-8", compresslevel=3) as out_fh:
            for raw in proc.stdout:
                # Cheap rejection before regex.
                if b"sensor:" not in raw or b"PacketTime:" not in raw:
                    continue
                try:
                    line = raw.decode("utf-8", errors="replace")
                except Exception:
                    continue
                m = PACKET_TIME_RE.search(line)
                if not m:
                    continue
                iso = f"{m.group(1)}T{m.group(2)}Z"
                # Strip trailing newline from line before re-appending; keep raw bytes otherwise.
                line = line.rstrip("\n").replace("\t", " ")
                out_fh.write(f"{iso}\t{line}\n")
                count += 1
                if first_ts is None or iso < first_ts:
                    first_ts = iso
                if last_ts is None or iso > last_ts:
                    last_ts = iso
    finally:
        proc.stdout.close()
        proc.wait()

    if count == 0:
        # No sensor data: drop the empty intermediate.
        try:
            out.unlink()
        except OSError:
            pass

    return {
        "src": str(src),
        "out": str(out) if count else "",
        "count": count,
        "first_ts": first_ts or "",
        "last_ts": last_ts or "",
    }


def gather_inputs(roots):
    seen = set()
    files = []
    for root in roots:
        root = Path(root).expanduser()
        if not root.is_dir():
            continue
        for p in sorted(root.glob("*.gz")):
            # Skip non-log gz like maxmind dbs (they don't live in these dirs but be safe).
            if p.name.endswith(".tar.gz"):
                continue
            rp = p.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            files.append(p)
    return files


def fmt_bytes(n):
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f}{u}"
        f /= 1024


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--input-dir",
        action="append",
        default=None,
        help="Input directory (repeatable). Default: ~/temp/sensor_logs and "
             "~/temp/sensor_logs/2025-03-20",
    )
    ap.add_argument(
        "--output-dir",
        default=str(Path.home() / "temp/sensor_logs/consolidated"),
    )
    ap.add_argument(
        "--output-name",
        default="merged.log.gz",
    )
    ap.add_argument(
        "--manifest-name",
        default="manifest.tsv",
    )
    ap.add_argument(
        "--tmp-dir",
        default=None,
        help="Scratch dir for per-file intermediates and sort spill. "
             "Default: <output-dir>/.tmp",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=max(2, (os.cpu_count() or 4) // 2),
        help="Parallel extraction workers.",
    )
    ap.add_argument(
        "--sort-mem",
        default="4G",
        help="GNU sort memory budget (-S).",
    )
    ap.add_argument(
        "--sort-parallel",
        type=int,
        default=max(2, (os.cpu_count() or 4) // 2),
        help="Parallelism for GNU sort (--parallel).",
    )
    ap.add_argument(
        "--max-files",
        type=int,
        default=0,
        help="Process at most N .gz files (0 = all). Use for smoke testing.",
    )
    ap.add_argument(
        "--skip-merge",
        action="store_true",
        help="Run extraction only; leave intermediates in place.",
    )
    ap.add_argument(
        "--keep-intermediate",
        action="store_true",
        help="Do not delete per-file intermediates after merge.",
    )
    args = ap.parse_args()

    roots = args.input_dir or [
        str(Path.home() / "temp/sensor_logs"),
        str(Path.home() / "temp/sensor_logs/2025-03-20"),
    ]
    output_dir = Path(args.output_dir).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = (Path(args.tmp_dir).expanduser() if args.tmp_dir
               else output_dir / ".tmp")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    final_path = output_dir / args.output_name
    manifest_path = output_dir / args.manifest_name

    files = gather_inputs(roots)
    if args.max_files:
        files = files[: args.max_files]
    if not files:
        print("No .gz files found.", file=sys.stderr)
        return 2

    total_in_bytes = sum(p.stat().st_size for p in files)
    print(f"[info] {len(files)} input .gz files, {fmt_bytes(total_in_bytes)} compressed")
    print(f"[info] workers={args.workers}  tmp={tmp_dir}  output={final_path}")

    # Build extraction job list (one per input file).
    tasks = []
    for p in files:
        # Flat namespace; include parent folder in the intermediate filename to avoid collisions.
        tag = f"{p.parent.name}__{p.name}"
        out_path = tmp_dir / f"{tag}.tsv.gz"
        tasks.append((str(p), str(out_path)))

    # Phase 1: parallel extraction.
    t0 = time.time()
    manifest_rows = []
    total_events = 0
    nonempty = 0
    with mp.Pool(processes=args.workers) as pool:
        for i, row in enumerate(pool.imap_unordered(extract_one, tasks, chunksize=1), 1):
            manifest_rows.append(row)
            if row["count"]:
                nonempty += 1
            total_events += row["count"]
            if i % 25 == 0 or i == len(tasks):
                elapsed = time.time() - t0
                rate = i / elapsed if elapsed else 0
                print(
                    f"[extract] {i}/{len(tasks)}  events={total_events:,}  "
                    f"non-empty={nonempty}  rate={rate:.2f} files/s",
                    file=sys.stderr,
                )

    # Write manifest sorted by first_ts so it doubles as a coverage map.
    manifest_rows.sort(key=lambda r: (r["first_ts"] or "9999", r["src"]))
    with open(manifest_path, "w", encoding="utf-8") as mf:
        mf.write("first_ts\tlast_ts\tsensor_lines\tsrc\tintermediate\n")
        for r in manifest_rows:
            mf.write(
                f"{r['first_ts']}\t{r['last_ts']}\t{r['count']}\t"
                f"{r['src']}\t{r['out']}\n"
            )
    print(f"[manifest] wrote {manifest_path}")

    print(
        f"[extract] done in {time.time()-t0:.1f}s: "
        f"{nonempty}/{len(tasks)} files had sensor data, "
        f"{total_events:,} total events"
    )

    if args.skip_merge:
        print("[info] --skip-merge set; stopping after extraction.")
        return 0

    intermediates = [r["out"] for r in manifest_rows if r["out"]]
    if not intermediates:
        print("[warn] no intermediates produced; nothing to merge.")
        return 0

    inter_size = sum(Path(p).stat().st_size for p in intermediates)
    print(f"[merge] {len(intermediates)} intermediates, "
          f"{fmt_bytes(inter_size)} compressed")

    # Phase 2: global sort + dedup.
    # zcat all intermediates -> sort -u (with gzip-compressed spill) -> gzip -> final.
    # Using shell pipeline so byte-streams stay out of Python.
    t1 = time.time()
    print(f"[merge] streaming sort -u  mem={args.sort_mem}  parallel={args.sort_parallel}")
    inter_list = " ".join(f"'{p}'" for p in intermediates)
    pipeline = (
        f"set -o pipefail; "
        f"LC_ALL=C zcat {inter_list} "
        f"| LC_ALL=C sort -u -S {args.sort_mem} --parallel={args.sort_parallel} "
        f"-T '{tmp_dir}' --compress-program=gzip "
        f"| gzip -c > '{final_path}.partial' "
        f"&& mv '{final_path}.partial' '{final_path}'"
    )
    rc = subprocess.call(["bash", "-c", pipeline])
    if rc != 0:
        print(f"[merge] FAILED rc={rc}", file=sys.stderr)
        return rc
    print(f"[merge] done in {time.time()-t1:.1f}s")

    # Final stats.
    final_size = final_path.stat().st_size
    line_count_cmd = f"zcat -- '{final_path}' | wc -l"
    res = subprocess.run(["bash", "-c", line_count_cmd], capture_output=True, text=True)
    try:
        final_lines = int(res.stdout.strip().split()[0])
    except Exception:
        final_lines = -1
    print(f"[done] {final_path}: {fmt_bytes(final_size)} gz, "
          f"{final_lines:,} unique events")
    if total_events and final_lines > 0:
        removed = total_events - final_lines
        print(f"[done] dedup: removed {removed:,} duplicates "
              f"({100*removed/total_events:.1f}% of extracted)")

    if not args.keep_intermediate:
        for p in intermediates:
            try:
                os.unlink(p)
            except OSError:
                pass
        # Clean tmp dir if empty.
        try:
            if not any(tmp_dir.iterdir()):
                shutil.rmtree(tmp_dir)
        except OSError:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())

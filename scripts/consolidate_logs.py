#!/usr/bin/env python3
"""
Consolidate raw honeypot syslog .gz files into a single sorted, deduplicated
event timeline, correcting clock skew on the honeypi00 sensor.

Pipeline
--------
1. Parallel extraction: for each input .gz file, `zcat` -> stream every line ->
   classify as (anchor | sensor | other) and:
     * Track the most recently seen "anchor" timestamp - FortiGate
       `date=YYYY-MM-DD time=HH:MM:SS tz="..."` or newsyslog ISO-UTC
       prefix.  These devices have correct clocks.
     * For sensor lines, parse `PacketTime:` (which is set by the
       potentially-broken honeypi00 clock).  Detect "run boundaries"
       (a backward jump in PacketTime or a > 1h forward jump) and
       at each new run, compute a per-run correction offset:
         offset = last_anchor_ts - PacketTime_at_run_start
       Within a run, `corrected_ts = PacketTime + offset` preserves the
       confirmed-correct intra-run incrementing.
     * If a sensor line appears before any anchor in the file, fall back
       to the filename + mtime to derive the file's real reference date
       (`local.<N>.gz` => mtime - 1 - N days, midnight UTC).
   Each retained sensor line is emitted as `<corrected_ISO_UTC>\\t<raw>`
   to a per-file gzipped intermediate.  The original (broken) PacketTime
   is NOT preserved in the output - it lives in the manifest's per-file
   skew stats instead.
2. Global merge: `LC_ALL=C sort -u` across all intermediates, piped into
   gzip, producing one consolidated `merged.log.gz`.  Because each line
   starts with an ISO 8601 UTC timestamp, lex sort == chronological.
3. Clock-skew report: after extraction, write a markdown + parquet
   summary of which input files showed clock skew, the first observed
   skew date (when honeypi00's clock broke), and the top files by
   max skew.

Scope
-----
Only honeypot sensor lines are kept - identified by the hostname
``honeypi00`` AND the program tag ``sensor:`` in the same line, with a
``PacketTime:<YYYY-MM-DD HH:MM:SS.ffffff>`` payload field.  Fortinet
firewall, newsyslog rotation, and other co-mingled syslog sources are
read as anchors but not emitted.

Output
------
~/temp/sensor_logs/consolidated/
    merged.log.gz       # <corrected_iso_utc>\\t<raw_line> per line
    manifest.tsv        # per-input-file: includes skew columns
~/git/SensorGrind_AI/output/reports/clock_skew/
    clock_skew.md
    clock_skew.parquet
"""

import argparse
import multiprocessing as mp
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Sensor PacketTime (set by honeypi00's potentially-broken clock).
# Bytes-level because we operate on the raw zcat byte stream.
PACKET_TIME_RE = re.compile(
    rb"PacketTime:(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+)"
)

# FortiGate-style anchor: `date=YYYY-MM-DD time=HH:MM:SS ... tz="-0700"`.
# The tz field appears later in the line; we capture it separately to
# convert local time to UTC.
FORTI_DT_RE = re.compile(rb'date=(\d{4}-\d{2}-\d{2})\s+time=(\d{2}:\d{2}:\d{2})')
FORTI_TZ_RE = re.compile(rb'tz="([+-]?\d{4})"')

# Newsyslog rotation lines that start with an ISO-8601 UTC timestamp.
# Example: `2026-05-28T07:00:01.713Z corona newsyslog[71564]: logfile turned over`
NEWSYSLOG_RE = re.compile(rb'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})')

# Identify honeypi00 sensor lines cheaply.
SENSOR_TOKEN = b"honeypi00 sensor:"
PACKETTIME_TOKEN = b"PacketTime:"

# Filename pattern: `local.<N>.gz`.  N = days back from the rotation
# reference (file mtime - 1).
LOCAL_N_RE = re.compile(r'^local\.(\d+)\.gz$')

# Run-boundary thresholds (in seconds of PacketTime delta).
RUN_BACKWARD_TOLERANCE = 0          # any backward jump -> new run
RUN_FORWARD_TOLERANCE  = 3600       # > 1h forward jump -> new run


def _tz_offset_minutes(tz_bytes: bytes) -> int:
    """Convert `-0700` / `+0530` style tz to UTC offset in minutes."""
    s = tz_bytes.decode("ascii", errors="replace")
    sign = -1 if s.startswith("-") else 1
    s = s.lstrip("+-")
    hh = int(s[:2])
    mm = int(s[2:4])
    return sign * (hh * 60 + mm)


def _filename_fallback_ref(src: Path) -> datetime | None:
    """Estimate a file's true reference date from its name + mtime.

    `local.<N>.gz` => (mtime_date - 1 - N) days, midnight UTC.  Returns
    None if the filename doesn't match the convention.
    """
    m = LOCAL_N_RE.match(src.name)
    if not m:
        return None
    n = int(m.group(1))
    try:
        mtime = datetime.fromtimestamp(src.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None
    ref = (mtime - timedelta(days=1 + n)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return ref


def extract_one(args):
    """Worker: read one .gz, emit corrected-timestamp TSV, return manifest row.

    Streaming pass:
      * Track `last_anchor_ts` from FortiGate `date=`/`time=`/`tz=` or
        newsyslog ISO-UTC prefix lines.  These devices have correct
        clocks and their timestamps are converted to UTC.
      * For sensor lines, parse PacketTime (UTC, but possibly very wrong
        due to honeypi00 clock skew).  Detect run boundaries (backward
        or > 1h forward jumps) and at each new run compute
        `offset = last_anchor_ts - PacketTime_at_run_start`.  Within a
        run, `corrected_ts = PacketTime + offset`.
      * Fallback when a sensor line precedes any anchor: derive the
        file's reference date from `local.<N>.gz` + mtime, midnight UTC.

    Returns a manifest row including per-file skew stats.
    """
    src_path, out_path = args
    src = Path(src_path)
    out = Path(out_path)

    fallback_ref: datetime | None = _filename_fallback_ref(src)

    first_corrected_ts: str | None = None
    last_corrected_ts: str | None = None
    first_orig_pt: str | None = None
    last_orig_pt: str | None = None

    last_anchor_ts: datetime | None = None
    first_anchor_ts: datetime | None = None
    last_packet_time: datetime | None = None
    run_offset = timedelta(0)
    run_offset_set = False

    # One entry per clock run: where it starts in corrected time and the
    # offset applied.  Detectors that keep state mask these boundaries,
    # because inter-arrival times that straddle two runs mix two offsets.
    runs: list[dict] = []

    sensor_count = 0
    anchor_count = 0
    run_count = 0
    max_skew_seconds = 0.0
    anchor_source = "none"

    proc = subprocess.Popen(
        ["zcat", str(src)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=1 << 20,
    )
    # Per-file intermediate writer: zstd is roughly 3-5x faster than
    # gzip at compresslevel=3 with comparable ratio.  We pipe lines into
    # `zstd -T0 -3` which writes the compressed `.tsv.zst` directly.
    # zstd handles its own buffered I/O; we feed it bytes via stdin.
    zstd_proc = subprocess.Popen(
        ["zstd", "-T0", "-3", "-q", "-f", "-o", str(out)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        bufsize=1 << 20,
    )
    out_fh = zstd_proc.stdin
    try:
        for raw in proc.stdout:
                # ---- anchor detection ----
                # FortiGate is by far the most common anchor; check first.
                m_fg = FORTI_DT_RE.search(raw)
                if m_fg:
                    d = m_fg.group(1).decode("ascii")
                    t = m_fg.group(2).decode("ascii")
                    m_tz = FORTI_TZ_RE.search(raw)
                    try:
                        local_dt = datetime.fromisoformat(f"{d}T{t}")
                    except ValueError:
                        local_dt = None
                    if local_dt is not None:
                        off_min = (_tz_offset_minutes(m_tz.group(1))
                                   if m_tz else 0)
                        anchor_utc = (local_dt - timedelta(minutes=off_min)
                                      ).replace(tzinfo=timezone.utc)
                        last_anchor_ts = anchor_utc
                        if first_anchor_ts is None:
                            first_anchor_ts = anchor_utc
                            anchor_source = "fortigate"
                        anchor_count += 1
                    # FortiGate lines never contain `honeypi00 sensor:`.
                    continue

                # Newsyslog ISO timestamp at start of line.
                m_ns = NEWSYSLOG_RE.match(raw)
                if m_ns:
                    d = m_ns.group(1).decode("ascii")
                    t = m_ns.group(2).decode("ascii")
                    try:
                        anchor_utc = datetime.fromisoformat(f"{d}T{t}").replace(
                            tzinfo=timezone.utc
                        )
                        last_anchor_ts = anchor_utc
                        if first_anchor_ts is None:
                            first_anchor_ts = anchor_utc
                            anchor_source = "newsyslog"
                        anchor_count += 1
                    except ValueError:
                        pass
                    continue

                # ---- sensor line ----
                if SENSOR_TOKEN not in raw or PACKETTIME_TOKEN not in raw:
                    continue
                m_pt = PACKET_TIME_RE.search(raw)
                if not m_pt:
                    continue
                d = m_pt.group(1).decode("ascii")
                t = m_pt.group(2).decode("ascii")
                try:
                    packet_time = datetime.fromisoformat(f"{d}T{t}").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    continue

                # ---- run boundary detection ----
                new_run = (
                    last_packet_time is None
                    or packet_time < last_packet_time - timedelta(
                        seconds=RUN_BACKWARD_TOLERANCE
                    )
                    or (packet_time - last_packet_time).total_seconds()
                       > RUN_FORWARD_TOLERANCE
                )
                if new_run:
                    if last_anchor_ts is not None:
                        anchor_for_run = last_anchor_ts
                    elif fallback_ref is not None:
                        anchor_for_run = fallback_ref
                        if anchor_source == "none":
                            anchor_source = "filename"
                    else:
                        last_packet_time = packet_time
                        continue
                    run_offset = anchor_for_run - packet_time
                    run_offset_set = True
                    run_count += 1
                    skew_sec = abs(run_offset.total_seconds())
                    if skew_sec > max_skew_seconds:
                        max_skew_seconds = skew_sec
                    runs.append({
                        "src":          str(src),
                        "run_idx":      run_count,
                        "run_start_ts": packet_time + run_offset,
                        "orig_pt":      packet_time,
                        "offset_s":     run_offset.total_seconds(),
                        "anchor_kind":  ("anchor" if last_anchor_ts is not None
                                         else "filename"),
                        "lines":        0,
                    })

                if not run_offset_set:
                    last_packet_time = packet_time
                    continue

                corrected = packet_time + run_offset
                iso = corrected.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

                # Rewrite the body's `PacketTime:` field with the corrected
                # value so downstream tools (parser, analyzers, ad-hoc grep)
                # read consistent timestamps regardless of whether they
                # parse the leading ISO column or the embedded PacketTime.
                # The original honeypi00 syslog prefix (e.g. `Feb 14 02:12:33`)
                # at the start of the message is left intact - it's not
                # used by any analyzer and discarding it would lose
                # ordering information about the raw stream.
                new_pt_bytes = (b"PacketTime:" + corrected.strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                ).encode("ascii"))
                raw_fixed = PACKET_TIME_RE.sub(new_pt_bytes, raw, count=1)
                try:
                    line = raw_fixed.decode("utf-8", errors="replace")
                except Exception:
                    last_packet_time = packet_time
                    continue
                line = line.rstrip("\n").replace("\t", " ")
                out_fh.write(f"{iso}\t{line}\n".encode("utf-8"))

                if first_corrected_ts is None or iso < first_corrected_ts:
                    first_corrected_ts = iso
                if last_corrected_ts is None or iso > last_corrected_ts:
                    last_corrected_ts = iso
                orig_iso = packet_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                if first_orig_pt is None or orig_iso < first_orig_pt:
                    first_orig_pt = orig_iso
                if last_orig_pt is None or orig_iso > last_orig_pt:
                    last_orig_pt = orig_iso

                sensor_count += 1
                runs[-1]["lines"] += 1
                last_packet_time = packet_time
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
        proc.wait()
        try:
            out_fh.close()
        except Exception:
            pass
        zstd_proc.wait()

    if sensor_count == 0:
        try:
            out.unlink()
        except OSError:
            pass

    return {
        "src":             str(src),
        "out":             str(out) if sensor_count else "",
        "count":           sensor_count,
        "first_ts":        first_corrected_ts or "",
        "last_ts":         last_corrected_ts or "",
        "first_orig_pt":   first_orig_pt or "",
        "last_orig_pt":    last_orig_pt or "",
        "anchor_count":    anchor_count,
        "run_count":       run_count,
        "max_skew_days":   round(max_skew_seconds / 86400.0, 3),
        "anchor_source":   anchor_source,
        "first_anchor_ts": (first_anchor_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
                            if first_anchor_ts else ""),
        "fallback_ref":    (fallback_ref.strftime("%Y-%m-%dT%H:%M:%SZ")
                            if fallback_ref else ""),
        "runs":            runs if sensor_count else [],
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


def write_clock_skew_report(rows: list[dict]) -> None:
    """Summarize per-file clock-skew stats to markdown + parquet.

    The honeypi00 sensor's clock drifted at some point; this report
    answers (a) WHEN did the skew first appear, (b) which files are
    affected, and (c) how bad was the worst skew.

    Output:
      ~/git/SensorGrind_AI/output/reports/clock_skew/clock_skew.md
      ~/git/SensorGrind_AI/output/reports/clock_skew/clock_skew.parquet
    """
    out_dir = (Path.home() / "git" / "SensorGrind_AI"
               / "output" / "reports" / "clock_skew")
    out_dir.mkdir(parents=True, exist_ok=True)

    SKEW_THRESHOLD_DAYS = 0.5   # mark as skewed once > 12h off

    # Order by the corrected first_ts so the timeline is chronological.
    rows_sorted = sorted(rows, key=lambda r: (r["first_ts"] or "9999",
                                              r["src"]))

    skewed = [r for r in rows_sorted
              if r["count"] > 0 and r["max_skew_days"] >= SKEW_THRESHOLD_DAYS]
    clean  = [r for r in rows_sorted
              if r["count"] > 0 and r["max_skew_days"] < SKEW_THRESHOLD_DAYS]

    first_skew_ts = skewed[0]["first_ts"] if skewed else ""
    last_skew_ts  = skewed[-1]["first_ts"] if skewed else ""
    max_skew      = max((r["max_skew_days"] for r in skewed), default=0.0)
    total_events_skewed = sum(r["count"] for r in skewed)
    total_events_clean  = sum(r["count"] for r in clean)
    total_events_all    = total_events_skewed + total_events_clean

    # Markdown.
    md = ["# clock_skew - honeypi00 sensor clock-skew detection", ""]
    md.append(
        "_Per-file scan of the consolidator's input set.  Each row is "
        "one source `.gz` file; `max_skew_days` is the largest absolute "
        "delta (in days) between the file's nearest accurate-clock "
        "anchor (FortiGate / newsyslog) and the sensor's `PacketTime` "
        "at the start of each detected run.  Skew > 12h is treated as "
        "evidence the honeypi00 clock was wrong._"
    )
    md.append("")
    md.append("## Summary")
    md.append("")
    md.append(f"- **Total files processed (with sensor data):** {len(rows_sorted)}")
    md.append(f"- **Files with clock skew (> 12h):** {len(skewed)}")
    md.append(f"- **Files with clock OK:** {len(clean)}")
    md.append(f"- **Worst observed skew:** {max_skew:,.1f} days")
    if first_skew_ts:
        md.append(
            f"- **First skewed-file corrected timestamp:** `{first_skew_ts}` "
            f"(events from this file onward were emitted by a broken-clock honeypi00)"
        )
        md.append(
            f"- **Most recent skewed-file corrected timestamp:** `{last_skew_ts}`"
        )
    md.append(
        f"- **Sensor events recovered from skewed files:** "
        f"{total_events_skewed:,} / {total_events_all:,} "
        f"({100*total_events_skewed/total_events_all if total_events_all else 0:.1f}%)"
    )
    md.append("")

    md.append("## Top 20 files by max skew")
    md.append("")
    md.append("| max_skew_days | sensor_lines | runs | anchor_source | "
              "corrected first_ts | original PacketTime first | src |")
    md.append("| ---: | ---: | ---: | --- | --- | --- | --- |")
    for r in sorted(skewed, key=lambda r: -r["max_skew_days"])[:20]:
        md.append(
            f"| {r['max_skew_days']:.1f} | {r['count']:,} | {r['run_count']} | "
            f"{r['anchor_source']} | `{r['first_ts']}` | `{r['first_orig_pt']}` | "
            f"`{Path(r['src']).name}` |"
        )
    md.append("")

    if skewed:
        md.append("## Timeline - first 30 skewed files in corrected-time order")
        md.append("")
        md.append("_Reading top-to-bottom: when did honeypi00's clock first "
                  "drift, and how bad was it on each day?_")
        md.append("")
        md.append("| corrected first_ts | max_skew_days | events | "
                  "original PacketTime first | src |")
        md.append("| --- | ---: | ---: | --- | --- |")
        for r in skewed[:30]:
            md.append(
                f"| `{r['first_ts']}` | {r['max_skew_days']:.1f} | {r['count']:,} | "
                f"`{r['first_orig_pt']}` | `{Path(r['src']).name}` |"
            )
        md.append("")

    md.append("## All clean (sub-12h-skew) files - first 20")
    md.append("")
    md.append("_Files where the honeypi00 clock matched the anchors well._")
    md.append("")
    md.append("| corrected first_ts | sensor_lines | max_skew_days | src |")
    md.append("| --- | ---: | ---: | --- |")
    for r in clean[:20]:
        md.append(
            f"| `{r['first_ts']}` | {r['count']:,} | {r['max_skew_days']:.3f} | "
            f"`{Path(r['src']).name}` |"
        )
    md.append("")

    (out_dir / "clock_skew.md").write_text("\n".join(md) + "\n")

    # Parquet for downstream report integration.
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        print("[skew] pyarrow not available; skipping parquet emit",
              file=sys.stderr)
        return
    schema = pa.schema([
        ("src",             pa.string()),
        ("sensor_lines",    pa.uint32()),
        ("max_skew_days",   pa.float32()),
        ("run_count",       pa.uint32()),
        ("anchor_count",    pa.uint32()),
        ("anchor_source",   pa.string()),
        ("first_ts",        pa.string()),
        ("last_ts",         pa.string()),
        ("first_orig_pt",   pa.string()),
        ("last_orig_pt",    pa.string()),
        ("first_anchor_ts", pa.string()),
        ("fallback_ref",    pa.string()),
        ("is_skewed",       pa.bool_()),
    ])
    rows_pq = [{
        "src":             r["src"],
        "sensor_lines":    int(r["count"]),
        "max_skew_days":   float(r["max_skew_days"]),
        "run_count":       int(r["run_count"]),
        "anchor_count":    int(r["anchor_count"]),
        "anchor_source":   r["anchor_source"],
        "first_ts":        r["first_ts"],
        "last_ts":         r["last_ts"],
        "first_orig_pt":   r["first_orig_pt"],
        "last_orig_pt":    r["last_orig_pt"],
        "first_anchor_ts": r["first_anchor_ts"],
        "fallback_ref":    r["fallback_ref"],
        "is_skewed":       r["max_skew_days"] >= SKEW_THRESHOLD_DAYS,
    } for r in rows_sorted if r["count"] > 0]
    pq.write_table(pa.Table.from_pylist(rows_pq, schema=schema),
                   out_dir / "clock_skew.parquet",
                   compression="zstd", compression_level=3)
    print(f"[skew] wrote {out_dir}/clock_skew.{{md,parquet}}",
          file=sys.stderr)


def write_clock_runs(rows: list[dict]) -> None:
    """One row per clock run, for src/sensormask.py run-boundary masking.

    Output:
      ~/git/SensorGrind_AI/output/reports/clock_skew/clock_runs.parquet
    """
    out_dir = (Path.home() / "git" / "SensorGrind_AI"
               / "output" / "reports" / "clock_skew")
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        print("[skew] pyarrow not available; skipping clock_runs emit",
              file=sys.stderr)
        return
    schema = pa.schema([
        ("src",          pa.string()),
        ("run_idx",      pa.uint32()),
        ("run_start_ts", pa.timestamp("us", tz="UTC")),
        ("orig_pt",      pa.timestamp("us", tz="UTC")),
        ("offset_s",     pa.float64()),
        ("anchor_kind",  pa.string()),
        ("lines",        pa.uint64()),
    ])
    runs = sorted((run for r in rows for run in r.get("runs", [])
                   if run["lines"] > 0),
                  key=lambda run: run["run_start_ts"])
    tmp = out_dir / "clock_runs.parquet.tmp"
    pq.write_table(pa.Table.from_pylist(runs, schema=schema), tmp,
                   compression="zstd", compression_level=3)
    tmp.replace(out_dir / "clock_runs.parquet")
    print(f"[skew] wrote {out_dir}/clock_runs.parquet ({len(runs):,} runs)",
          file=sys.stderr)


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
        out_path = tmp_dir / f"{tag}.tsv.zst"
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

    # Write manifest sorted by first_ts (corrected) so it doubles as a coverage map.
    manifest_rows.sort(key=lambda r: (r["first_ts"] or "9999", r["src"]))
    manifest_cols = [
        "first_ts", "last_ts", "sensor_lines",
        "first_orig_pt", "last_orig_pt",
        "anchor_count", "run_count",
        "max_skew_days", "anchor_source",
        "first_anchor_ts", "fallback_ref",
        "src", "intermediate",
    ]
    with open(manifest_path, "w", encoding="utf-8") as mf:
        mf.write("\t".join(manifest_cols) + "\n")
        for r in manifest_rows:
            mf.write("\t".join([
                r["first_ts"], r["last_ts"], str(r["count"]),
                r["first_orig_pt"], r["last_orig_pt"],
                str(r["anchor_count"]), str(r["run_count"]),
                str(r["max_skew_days"]), r["anchor_source"],
                r["first_anchor_ts"], r["fallback_ref"],
                r["src"], r["out"],
            ]) + "\n")
    print(f"[manifest] wrote {manifest_path}")

    print(
        f"[extract] done in {time.time()-t0:.1f}s: "
        f"{nonempty}/{len(tasks)} files had sensor data, "
        f"{total_events:,} total events"
    )

    # Emit clock-skew report from the per-file manifest rows.
    write_clock_skew_report(manifest_rows)
    write_clock_runs(manifest_rows)

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
    # Intermediates are zstd-compressed (`.tsv.zst`); sort spill is also
    # zstd via `--compress-program=zstd` — both are ~3-5x faster than
    # gzip at similar ratio.  The final `merged.log.gz` stays gzip
    # because every downstream consumer (parser, ad-hoc grep, the
    # archived script suite) expects gzip and the final-write CPU is
    # not the bottleneck.
    t1 = time.time()
    print(f"[merge] streaming sort -u  mem={args.sort_mem}  parallel={args.sort_parallel}")
    inter_list = " ".join(f"'{p}'" for p in intermediates)
    pipeline = (
        f"set -o pipefail; "
        f"LC_ALL=C zstd -dc -T0 {inter_list} "
        f"| LC_ALL=C sort -u -S {args.sort_mem} --parallel={args.sort_parallel} "
        f"-T '{tmp_dir}' --compress-program=zstd "
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

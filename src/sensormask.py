#!/usr/bin/env python3
"""
sensormask — "sensor off" and clock-run-boundary mask for stateful detectors.

Any detector that keeps state over time (leaky integrators, reservoirs, HTM
cells, rolling z-scores, decayed prototypes) must know when the sensor was
not recording.  Otherwise it learns an outage as "quiet normal" and then
flags the restart as a huge burst.  No analyzer masked the 2025-11-12 ->
2026-01-28 outage before this stage.

Two interval kinds are emitted:

  gap           a run of >= --gap-minutes consecutive minutes with zero
                packets.  At the corpus mean of ~19 packets/s, a silent
                half hour is a sensor / collector outage, not an Internet
                lull.  Derived from the packets table itself, so it works on
                any parse without re-running the consolidator.
  run_boundary  a clock-skew run start from the consolidator
                (output/reports/clock_skew/clock_runs.parquet, written by
                scripts/consolidate_logs.py).  Each run carries its own
                1-second-resolution offset, so inter-arrival times that
                straddle a boundary are untrustworthy.  The interval spans
                +/- --boundary-pad-seconds around the run start.  Skipped
                when the consolidator has not emitted the runs file.

Consumers call ``lib.load_sensor_mask()`` / ``lib.mask_predicate()`` and
either drop masked rows from fit windows or reset per-entity state at each
interval end.

Output:
  output/reports/sensormask/sensormask.{parquet,md}
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = lib.SENSORMASK_SCHEMA


def _gaps(con, where: str, gap_minutes: int) -> list[dict]:
    """Zero-packet runs >= gap_minutes, found from consecutive active minutes.

    Only active minutes are materialized (<= ~1M rows for the full corpus),
    and a gap is the space between two consecutive active minutes.
    """
    rows = con.execute(f"""
        WITH m AS (
            SELECT DISTINCT date_trunc('minute', ts) AS minute
            FROM packets WHERE {where}
        ), seq AS (
            SELECT minute,
                   lead(minute) OVER (ORDER BY minute) AS next_minute
            FROM m
        )
        SELECT minute + INTERVAL 1 MINUTE AS start_ts,
               next_minute               AS end_ts
        FROM seq
        WHERE next_minute IS NOT NULL
          AND next_minute - minute > to_minutes({gap_minutes}::BIGINT)
        ORDER BY start_ts
    """).fetchall()
    out = []
    for start, end in rows:
        out.append({
            "start_ts":   start,
            "end_ts":     end,
            "kind":       "gap",
            "duration_s": (end - start).total_seconds(),
            "source":     f"packets: >= {gap_minutes} silent minutes",
        })
    return out


def _run_boundaries(pad_s: float) -> list[dict]:
    path = lib.CLOCK_RUNS_PATH
    if not path.exists() or path.stat().st_size == 0:
        print(f"[sensormask] no {path.name}; run boundaries not masked "
              "(re-run scripts/consolidate_logs.py to emit them)",
              file=sys.stderr)
        return []
    import pyarrow.parquet as pq
    t = pq.read_table(path, columns=["run_start_ts", "offset_s", "src"])
    pad = _dt.timedelta(seconds=pad_s)
    out = []
    for start, offset_s, src in zip(t["run_start_ts"].to_pylist(),
                                    t["offset_s"].to_pylist(),
                                    t["src"].to_pylist()):
        if start is None:
            continue
        out.append({
            "start_ts":   start - pad,
            "end_ts":     start + pad,
            "kind":       "run_boundary",
            "duration_s": 2 * pad_s,
            "source":     f"clock run in {Path(src).name} "
                          f"(offset {offset_s:+.0f}s)",
        })
    return out


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck()
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))
    span = con.execute(f"SELECT min(ts), max(ts), count(*) FROM packets "
                       f"WHERE {where}").fetchone()
    gaps = _gaps(con, where, args.gap_minutes)
    con.close()
    bounds = _run_boundaries(args.boundary_pad_seconds)
    rows = sorted(gaps + bounds, key=lambda r: r["start_ts"])
    print(f"[sensormask] {len(gaps):,} gaps, {len(bounds):,} run boundaries",
          file=sys.stderr)

    gap_days = sum(r["duration_s"] for r in gaps) / 86400.0
    longest = sorted(gaps, key=lambda r: -r["duration_s"])[:20]
    md = [
        f"- corpus span: {span[0]} -> {span[1]} ({span[2]:,} packets)",
        f"- gap threshold: {args.gap_minutes} silent minutes",
        f"- gaps: {len(gaps):,} totalling {gap_days:.2f} days",
        f"- clock-run boundaries: {len(bounds):,} "
        f"(+/- {args.boundary_pad_seconds:.0f}s each)",
        "",
        "Stateful detectors must drop masked minutes from fit windows and "
        "reset per-entity state at the end of each interval.",
        "",
        "## Longest gaps",
        "",
        lib.markdown_table([
            {"start_ts": r["start_ts"], "end_ts": r["end_ts"],
             "days": round(r["duration_s"] / 86400.0, 3)} for r in longest
        ]),
    ]
    return lib.Report(name="sensormask", rows=rows, schema=RESULT_SCHEMA,
                      markdown="\n".join(md) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    ap.add_argument("--gap-minutes", type=int, default=30,
                    help="Silent minutes that count as a sensor outage.")
    ap.add_argument("--boundary-pad-seconds", type=float, default=5.0,
                    help="Half-width of each clock-run-boundary interval "
                         "(the skew anchors have 1 s resolution).")
    args = ap.parse_args()
    paths = run(args).write()
    print(f"[sensormask] wrote {paths['parquet']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

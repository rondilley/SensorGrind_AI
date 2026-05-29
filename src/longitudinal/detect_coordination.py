#!/usr/bin/env python3
"""
longitudinal/detect_coordination — find synchronized attack waves.

Two complementary detectors:

  1. Payload-synchronized waves: for each payload SHA-256 sent by >=N
     distinct IPs, compute how tightly the first-seen timestamps
     cluster. Tight clusters (median IP-arrival in < 1 hour) indicate
     a coordinated wave (C2 kick, fresh botnet payload, exploit
     campaign launch).

  2. Arrival bursts: time-bucket each minute and count distinct
     FIRST-EVER-APPEARED src_ips. Buckets with >5x the median rate
     mark moments when a wave of new IPs hit the sensor at once.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib

OUT_DIR = lib.OUTPUT_DIR / "patterns" / "coordination"

WAVE_SCHEMA = pa.schema([
    ("payload_sha256",  pa.binary(32)),
    ("l7_proto",        pa.string()),
    ("ip_count",        pa.uint32()),
    ("first_seen",      pa.timestamp("us", tz="UTC")),
    ("last_seen",       pa.timestamp("us", tz="UTC")),
    ("span_minutes",    pa.float32()),
    ("median_ipd_sec",  pa.float32()),
    ("tightness",       pa.float32()),
    ("sample_ips",      pa.string()),
])

BURST_SCHEMA = pa.schema([
    ("bucket_start",    pa.timestamp("us", tz="UTC")),
    ("new_ip_count",    pa.uint32()),
    ("baseline",        pa.float32()),
    ("ratio",           pa.float32()),
])


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    con.execute("SET threads=4")
    con.execute("SET preserve_insertion_order=false")
    lib.register_views(con)

    # ---- 1a. find multi-sender payloads (small result set) ----
    print("[coord] pass 1: finding multi-sender payloads...", file=sys.stderr)
    candidates = con.execute(f"""
        SELECT payload_sha256, count(DISTINCT src_ip) AS n_ips
        FROM packets
        WHERE payload_sha256 IS NOT NULL AND payload_len > 0
        GROUP BY payload_sha256
        HAVING count(DISTINCT src_ip) >= {args.min_ips}
        ORDER BY n_ips DESC
        LIMIT {args.max_waves}
    """).fetchall()
    print(f"[coord]   {len(candidates):,} multi-sender payloads", file=sys.stderr)

    if not candidates:
        waves = []
    else:
        con.execute("CREATE TEMP TABLE wave_sha(sha BLOB)")
        con.executemany("INSERT INTO wave_sha VALUES (?)", [(c[0],) for c in candidates])

        # ---- 1b. for those payloads, compute timing details ----
        print("[coord] pass 2: timing details + sample IPs...", file=sys.stderr)
        timing_rows = con.execute("""
            WITH first_per_ip AS (
                SELECT p.payload_sha256, p.src_ip,
                       min(p.ts) AS first_ts,
                       any_value(p.l7_proto) AS l7
                FROM packets p JOIN wave_sha w ON p.payload_sha256 = w.sha
                GROUP BY p.payload_sha256, p.src_ip
            ),
            with_delta AS (
                SELECT payload_sha256, l7, first_ts, src_ip,
                       EXTRACT(EPOCH FROM first_ts) -
                         EXTRACT(EPOCH FROM min(first_ts)
                                           OVER (PARTITION BY payload_sha256)) AS ipd_sec
                FROM first_per_ip
            )
            SELECT payload_sha256, any_value(l7) AS l7,
                   count(*) AS ip_count,
                   min(first_ts) AS first_seen,
                   max(first_ts) AS last_seen,
                   EXTRACT(EPOCH FROM (max(first_ts) - min(first_ts))) / 60.0 AS span_min,
                   median(ipd_sec) AS median_ipd,
                   list(src_ip ORDER BY first_ts)[:10] AS sample_ips
            FROM with_delta
            GROUP BY payload_sha256
            ORDER BY ip_count DESC
        """).fetchall()
        waves = timing_rows

    wave_rows: list[dict] = []
    for r in waves:
        sha, l7, n_ips, first, last, span_min, med_ipd, samples = r
        # tightness: ip_count per minute (higher = more synchronized)
        tightness = n_ips / max(span_min, 1.0)
        wave_rows.append({
            "payload_sha256": sha,
            "l7_proto": lib.L7_NAME.get(l7, "unknown"),
            "ip_count": n_ips, "first_seen": first, "last_seen": last,
            "span_minutes": float(span_min or 0),
            "median_ipd_sec": float(med_ipd or 0),
            "tightness": float(tightness),
            "sample_ips": ", ".join(samples or []),
        })
    wave_rows.sort(key=lambda r: r["tightness"], reverse=True)
    print(f"[coord] {len(wave_rows):,} multi-IP payloads", file=sys.stderr)

    # ---- 2. arrival bursts: minute buckets of new IPs ----
    print("[coord] computing per-minute new-IP arrival rate...", file=sys.stderr)
    bursts = con.execute("""
        WITH ip_first AS (
            SELECT src_ip, min(ts) AS first_ts FROM packets GROUP BY src_ip
        ),
        per_minute AS (
            SELECT date_trunc('minute', first_ts) AS bucket,
                   count(*) AS new_ips
            FROM ip_first
            GROUP BY bucket
        )
        SELECT bucket, new_ips FROM per_minute
        WHERE new_ips >= 5
        ORDER BY new_ips DESC
        LIMIT 5000
    """).fetchall()
    con.close()

    # Compute baseline from the top tail and ratios.
    values = np.array([b[1] for b in bursts], dtype=np.float64)
    baseline = float(np.median(values)) if values.size else 1.0
    burst_rows = [{
        "bucket_start": b[0],
        "new_ip_count": int(b[1]),
        "baseline": baseline,
        "ratio": float(b[1] / max(baseline, 1.0)),
    } for b in bursts]
    burst_rows = [r for r in burst_rows if r["ratio"] >= args.min_burst_ratio]
    burst_rows.sort(key=lambda r: r["ratio"], reverse=True)
    print(f"[coord] {len(burst_rows):,} arrival-burst minute buckets above "
          f"{args.min_burst_ratio}x median ({baseline:.1f})", file=sys.stderr)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(wave_rows, schema=WAVE_SCHEMA),
                   OUT_DIR / "payload_waves.parquet",
                   compression="zstd", compression_level=3)
    pq.write_table(pa.Table.from_pylist(burst_rows, schema=BURST_SCHEMA),
                   OUT_DIR / "arrival_bursts.parquet",
                   compression="zstd", compression_level=3)

    md_lines = ["# Coordination detection", "",
                "## Top 30 tightest payload-synchronized waves",
                "",
                f"_Waves = a single payload sha256 sent by {args.min_ips}+ "
                f"distinct IPs, ranked by tightness (IPs per minute of spread)._",
                "",
                "| ip_count | first_seen | span_min | median_ipd_s | l7 | sample_ips |",
                "| --- | --- | --- | --- | --- | --- |"]
    for r in wave_rows[:30]:
        md_lines.append(f"| {r['ip_count']:,} | {r['first_seen']} | "
                        f"{r['span_minutes']:.1f} | {r['median_ipd_sec']:.1f} | "
                        f"{r['l7_proto']} | {r['sample_ips']} |")

    md_lines.extend(["", "## Top 30 arrival-burst minutes",
                     "",
                     f"_Median minute has {baseline:.0f} new IPs; thresholds at "
                     f"{args.min_burst_ratio}x baseline._",
                     "",
                     "| bucket_start | new_ips | ratio_vs_median |",
                     "| --- | --- | --- |"])
    for r in burst_rows[:30]:
        md_lines.append(f"| {r['bucket_start']} | {r['new_ip_count']:,} | "
                        f"{r['ratio']:.1f}x |")
    (OUT_DIR / "coordination.md").write_text("\n".join(md_lines) + "\n")
    print(f"[coord] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-ips", type=int, default=10)
    ap.add_argument("--max-waves", type=int, default=2000)
    ap.add_argument("--min-burst-ratio", type=float, default=5.0)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

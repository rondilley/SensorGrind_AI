#!/usr/bin/env python3
"""
longitudinal/detect_coordination — find leading edges of attack campaigns.

Two complementary detectors:

  1. **Campaign-onset payload waves**: for each payload SHA-256 sent by
     >=N distinct IPs, compute when 5%/25%/50%/75%/95% of IPs first
     touched the sensor.  The (p5 -> p95) window is the *burst window*
     and the (p25 -> p75) window is the *peak window*.  A campaign is
     a payload whose burst window is small relative to the corpus span
     - i.e. most senders showed up in a brief slice of time, not
     spread evenly across years.  Always-on background payloads
     (masscan SYN probes, ubiquitous TLS fingerprints) are filtered
     out via `burst_window_days < CAMPAIGN_BURST_FRAC * corpus_span`.

     Each campaign carries: launch_ts (p5), peak_day (day with most
     new senders), decay_ts (p95), burst_window_days, density_score
     (ip_count * corpus_span / burst_window) for ranking.

  2. **Arrival bursts**: time-bucket each minute and count distinct
     FIRST-EVER-APPEARED src_ips.  Buckets with >5x the median rate
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
    ("launch_ts",       pa.timestamp("us", tz="UTC")),  # p5  of per-IP first-arrival
    ("p25_ts",          pa.timestamp("us", tz="UTC")),  # p25
    ("median_ts",       pa.timestamp("us", tz="UTC")),  # p50
    ("p75_ts",          pa.timestamp("us", tz="UTC")),  # p75
    ("decay_ts",        pa.timestamp("us", tz="UTC")),  # p95
    ("peak_day",        pa.timestamp("us", tz="UTC")),  # UTC midnight of busiest day
    ("peak_count",      pa.uint32()),                   # IPs first-seen on peak_day
    ("burst_window_days", pa.float32()),                # (p95 - p5) in days
    ("peak_window_days",  pa.float32()),                # (p75 - p25) in days
    ("span_minutes",    pa.float32()),
    ("median_ipd_sec",  pa.float32()),
    ("tightness",       pa.float32()),                  # ip_count / burst_window_days
    ("density_score",   pa.float32()),                  # ip_count * corpus_span / burst_window
    ("is_campaign",     pa.bool_()),                    # passed always-on filter
    ("sample_ips",      pa.string()),
])

# A payload is a real campaign only when its burst window is small
# relative to the corpus span.  60% means: half the year+ of arrivals
# could still qualify, but anything wider than that is just background.
CAMPAIGN_BURST_FRAC = 0.60

BURST_SCHEMA = pa.schema([
    ("bucket_start",    pa.timestamp("us", tz="UTC")),
    ("new_ip_count",    pa.uint32()),
    ("baseline",        pa.float32()),
    ("ratio",           pa.float32()),
])


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    # Default threads = cpu/2 from sg.lib.duck() is appropriate for the
    # multi-pass 1.1 B-row aggregate; the previous threads=4 cap was
    # leaving cores idle on multi-core hosts.
    con.execute("SET preserve_insertion_order=false")
    lib.register_views(con)

    # ---- single read of `packets` -> per-(payload, src_ip) staging ----
    # The previous implementation issued 3 separate full scans of the
    # 1.1B-row view: one for multi-sender candidate shas, one for
    # per-payload timing percentiles via wave_sha JOIN, and one for the
    # arrival-bursts new-IP-per-minute computation.  Both candidate
    # discovery and timing analysis aggregate at (payload_sha256, src_ip)
    # granularity, so we materialize that once and derive everything
    # else from it.  Arrival bursts still need an unfiltered view (an IP
    # that sent only SYN scans has no payload), so they get their own
    # second pass.
    print("[coord] pass 1: per-(payload, src_ip) staging from packets...",
          file=sys.stderr)
    con.execute("""
        CREATE TEMP TABLE first_per_payload_ip AS
        SELECT p.payload_sha256, p.src_ip,
               min(p.ts) AS first_ts,
               any_value(p.l7_proto) AS l7
        FROM packets p
        WHERE p.payload_sha256 IS NOT NULL AND p.payload_len > 0
        GROUP BY p.payload_sha256, p.src_ip
    """)
    staging_n = con.execute(
        "SELECT count(*) FROM first_per_payload_ip"
    ).fetchone()[0]
    print(f"[coord]   {staging_n:,} (payload, src_ip) tuples staged",
          file=sys.stderr)

    # Candidate multi-sender payloads: cheap aggregation on the staging table.
    con.execute(f"""
        CREATE TEMP TABLE wave_sha AS
        SELECT payload_sha256
        FROM first_per_payload_ip
        GROUP BY payload_sha256
        HAVING count(*) >= {int(args.min_ips)}
        ORDER BY count(*) DESC
        LIMIT {int(args.max_waves)}
    """)
    candidate_count = con.execute("SELECT count(*) FROM wave_sha").fetchone()[0]
    print(f"[coord]   {candidate_count:,} multi-sender payloads",
          file=sys.stderr)

    if candidate_count == 0:
        waves = []
        corpus_span_days = 1.0
    else:
        # Corpus span: parquet min/max stats — effectively metadata-only,
        # no scan.  Used to compute density_score and the always-on cutoff.
        corpus_row = con.execute(
            "SELECT date_diff('day', min(ts), max(ts)) FROM packets"
        ).fetchone()
        corpus_span_days = float(corpus_row[0] or 1)
        max_burst_days = corpus_span_days * CAMPAIGN_BURST_FRAC
        print(f"[coord] corpus span = {corpus_span_days:.0f} days; "
              f"campaign cutoff = burst_window < {max_burst_days:.0f} days",
              file=sys.stderr)

        # Per-payload percentile + peak-day analysis runs entirely off
        # the staging table — no further scan of `packets`.
        print("[coord] pass 2: per-payload first-arrival percentiles "
              "+ peak-day + sample IPs (from staging, no packets scan)...",
              file=sys.stderr)
        timing_rows = con.execute("""
            WITH wave_first AS (
                SELECT fp.payload_sha256, fp.src_ip, fp.first_ts, fp.l7
                FROM first_per_payload_ip fp
                JOIN wave_sha w ON fp.payload_sha256 = w.payload_sha256
            ),
            per_day AS (
                SELECT payload_sha256,
                       date_trunc('day', first_ts) AS day,
                       count(*) AS n
                FROM wave_first
                GROUP BY 1, 2
            ),
            peaks AS (
                SELECT payload_sha256,
                       arg_max(day, n)  AS peak_day,
                       max(n)           AS peak_count
                FROM per_day
                GROUP BY 1
            ),
            with_epoch AS (
                SELECT payload_sha256, l7, src_ip, first_ts,
                       epoch(first_ts) AS first_epoch,
                       EXTRACT(EPOCH FROM first_ts) -
                         EXTRACT(EPOCH FROM min(first_ts)
                                           OVER (PARTITION BY payload_sha256)) AS ipd_sec
                FROM wave_first
            )
            SELECT
                we.payload_sha256,
                any_value(we.l7)                                  AS l7,
                count(*)                                          AS ip_count,
                min(we.first_ts)                                  AS first_seen,
                max(we.first_ts)                                  AS last_seen,
                to_timestamp(quantile_cont(we.first_epoch, 0.05)) AS launch_ts,
                to_timestamp(quantile_cont(we.first_epoch, 0.25)) AS p25_ts,
                to_timestamp(quantile_cont(we.first_epoch, 0.50)) AS median_ts,
                to_timestamp(quantile_cont(we.first_epoch, 0.75)) AS p75_ts,
                to_timestamp(quantile_cont(we.first_epoch, 0.95)) AS decay_ts,
                pk.peak_day,
                pk.peak_count,
                EXTRACT(EPOCH FROM (max(we.first_ts) - min(we.first_ts)))/60.0 AS span_min,
                median(we.ipd_sec)                                AS median_ipd,
                list(we.src_ip ORDER BY we.first_ts)[:10]         AS sample_ips
            FROM with_epoch we
            LEFT JOIN peaks pk ON pk.payload_sha256 = we.payload_sha256
            GROUP BY we.payload_sha256, pk.peak_day, pk.peak_count
            ORDER BY ip_count DESC
        """).fetchall()
        waves = timing_rows

    wave_rows: list[dict] = []
    for r in waves:
        (sha, l7, n_ips, first, last,
         launch_ts, p25_ts, median_ts, p75_ts, decay_ts,
         peak_day, peak_count, span_min, med_ipd, samples) = r
        burst_window_days = float(((decay_ts - launch_ts).total_seconds() if
                                   launch_ts and decay_ts else 0) / 86400.0)
        peak_window_days = float(((p75_ts - p25_ts).total_seconds() if
                                  p25_ts and p75_ts else 0) / 86400.0)
        tightness = float(n_ips) / max(burst_window_days, 1 / 1440.0)
        density_score = (float(n_ips) * corpus_span_days /
                         max(burst_window_days, 1 / 1440.0))
        is_campaign = (burst_window_days > 0 and
                       burst_window_days < CAMPAIGN_BURST_FRAC * corpus_span_days)
        wave_rows.append({
            "payload_sha256": sha,
            "l7_proto": lib.L7_NAME.get(l7, "unknown"),
            "ip_count": n_ips,
            "first_seen": first, "last_seen": last,
            "launch_ts": launch_ts, "p25_ts": p25_ts,
            "median_ts": median_ts, "p75_ts": p75_ts, "decay_ts": decay_ts,
            "peak_day": peak_day, "peak_count": int(peak_count or 0),
            "burst_window_days": burst_window_days,
            "peak_window_days":  peak_window_days,
            "span_minutes": float(span_min or 0),
            "median_ipd_sec": float(med_ipd or 0),
            "tightness": tightness,
            "density_score": density_score,
            "is_campaign": is_campaign,
            "sample_ips": ", ".join(samples or []),
        })
    # Rank by density_score (combines campaign concentration + scale).
    wave_rows.sort(key=lambda r: r["density_score"], reverse=True)
    campaign_count = sum(1 for r in wave_rows if r["is_campaign"])
    print(f"[coord] {len(wave_rows):,} multi-IP payloads, "
          f"{campaign_count:,} flagged as campaigns "
          f"(burst_window < {CAMPAIGN_BURST_FRAC*100:.0f}% of corpus span)",
          file=sys.stderr)

    # ---- pass 3: arrival bursts (single pass; SYN-only IPs have no
    #              payload so this still needs the full unfiltered view) ----
    print("[coord] pass 3: per-minute new-IP arrival rate...", file=sys.stderr)
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
                "## Top 50 campaigns by density_score",
                "",
                f"_A 'campaign' is a payload sha256 sent by {args.min_ips}+ "
                f"distinct IPs where the p5->p95 first-arrival window "
                f"covers less than {CAMPAIGN_BURST_FRAC*100:.0f}% of the "
                f"{corpus_span_days:.0f}-day corpus span (i.e. the bulk "
                f"of senders showed up in a focused slice of time, not "
                f"spread across years).  density_score = "
                f"ip_count * (corpus_span_days / burst_window_days)._",
                "",
                "| launch_ts (p5) | peak_day | decay_ts (p95) | "
                "burst_d | ip_count | peak_d_ips | l7 | sample_ips |",
                "| --- | --- | --- | ---: | ---: | ---: | --- | --- |"]
    campaigns_only = [r for r in wave_rows if r["is_campaign"]]
    for r in campaigns_only[:50]:
        md_lines.append(
            f"| {r['launch_ts']} | {r['peak_day']} | {r['decay_ts']} | "
            f"{r['burst_window_days']:.1f} | {r['ip_count']:,} | "
            f"{r['peak_count']:,} | {r['l7_proto']} | {r['sample_ips']} |"
        )

    bg_rows = [r for r in wave_rows if not r["is_campaign"]][:10]
    if bg_rows:
        md_lines.extend(["", "## Always-on background payloads (top 10)", "",
                         "_Excluded from campaign ranking because their "
                         "burst window spans nearly the whole corpus._",
                         "",
                         "| ip_count | burst_d | first_seen | last_seen | l7 |",
                         "| ---: | ---: | --- | --- | --- |"])
        for r in bg_rows:
            md_lines.append(
                f"| {r['ip_count']:,} | {r['burst_window_days']:.0f} | "
                f"{r['first_seen']} | {r['last_seen']} | {r['l7_proto']} |"
            )

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

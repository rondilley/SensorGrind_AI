#!/usr/bin/env python3
"""
longitudinal/detect_changepoints — change-point detection on per-entity
daily activity time series across the full corpus span.

For each of the top-N IPs (by packet count) we build a daily packet
count series and run PELT change-point detection. Detected change
points indicate moments when the IP's behavior shifted: started
scanning a new port range, joined a new campaign, switched tools, etc.

Same logic applies to top-N campaigns (using campaign_id from the
campaign analyzer, mapping back to its sample_ips).
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

OUT_DIR = lib.OUTPUT_DIR / "patterns" / "changepoints"

SCHEMA = pa.schema([
    ("entity_type",   pa.string()),
    ("entity_id",     pa.string()),
    ("change_date",   pa.string()),
    ("idx",           pa.uint16()),
    ("series_len",    pa.uint16()),
    ("before_mean",   pa.float32()),
    ("after_mean",    pa.float32()),
    ("magnitude",     pa.float32()),
])


def _mbic_penalty(series: np.ndarray, scale: float = 1.0) -> float:
    """Modified-BIC penalty for PELT, length- AND variance-adaptive.

    Multi-AI methodology review flagged the previous fixed pen=10.0 as
    a tunable that over-fits short series (lots of spurious change
    points) and under-fits long ones (entire 6-year shifts get missed).
    mBIC sets pen = 2 * sigma^2 * log(n) per Zhang & Siegmund 2007.
    The ``scale`` knob multiplies the result so the operator can keep
    the old --penalty CLI as a relative dial.
    """
    n = len(series)
    if n < 4:
        return 0.0
    # MAD-based sigma is robust to the change points themselves.
    diffs = np.diff(series.astype(np.float64))
    mad = float(np.median(np.abs(diffs - np.median(diffs))))
    sigma2 = max(mad * 1.4826, 1.0) ** 2
    return float(scale * 2.0 * sigma2 * np.log(max(n, 2)))


def find_changepoints(series: np.ndarray,
                      pen_scale: float = 1.0,
                      min_size: int = 7) -> list[int]:
    import ruptures as rpt
    if len(series) < 2 * min_size:
        return []
    algo = rpt.Pelt(model="rbf", min_size=min_size).fit(
        series.astype(np.float64)
    )
    pen = _mbic_penalty(series, scale=pen_scale)
    bkps = algo.predict(pen=pen)
    # ruptures returns endpoints including len(series); we want change indices.
    return [b for b in bkps if 0 < b < len(series)]


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    # ---- Top IPs by packet count ----
    print(f"[changepoints] selecting top {args.top_ips} IPs...", file=sys.stderr)
    top_ips = con.execute(f"""
        SELECT src_ip, count(*) AS n
        FROM packets GROUP BY src_ip
        HAVING count(DISTINCT dt) >= {args.min_days}
        ORDER BY n DESC LIMIT {args.top_ips}
    """).fetchall()
    print(f"[changepoints] {len(top_ips):,} IPs with {args.min_days}+ active days", file=sys.stderr)

    if not top_ips:
        con.close()
        return 0

    # Batched per-IP daily series via a single GROUP BY join against a temp table.
    print("[changepoints] fetching daily activity for all selected IPs (single query)...",
          file=sys.stderr)
    con.execute("CREATE TEMP TABLE cp_ips(ip VARCHAR)")
    con.executemany("INSERT INTO cp_ips VALUES (?)", [(ip,) for ip, _ in top_ips])
    daily_rows = con.execute("""
        SELECT p.src_ip, CAST(p.ts AS DATE) AS d, count(*) AS c
        FROM packets p JOIN cp_ips t ON p.src_ip = t.ip
        GROUP BY p.src_ip, d
        ORDER BY p.src_ip, d
    """).fetchall()
    print(f"[changepoints] {len(daily_rows):,} (ip, date, count) rows", file=sys.stderr)

    series_per_ip: dict[str, list] = {}
    for ip, d, c in daily_rows:
        series_per_ip.setdefault(ip, []).append((d, int(c)))

    print("[changepoints] running PELT per IP...", file=sys.stderr)
    out_rows: list[dict] = []
    for i, (ip, _) in enumerate(top_ips):
        if i and i % 50 == 0:
            print(f"[changepoints]   {i}/{len(top_ips)}", file=sys.stderr)
        items = series_per_ip.get(ip, [])
        if len(items) < args.min_days:
            continue
        dates = [r[0] for r in items]
        series = np.array([r[1] for r in items], dtype=np.float64)
        bkps = find_changepoints(series, pen_scale=args.penalty_scale,
                                 min_size=args.min_segment)
        for bk in bkps:
            before = series[:bk]
            after = series[bk:]
            before_mean = float(before.mean()) if len(before) else 0.0
            after_mean = float(after.mean()) if len(after) else 0.0
            magnitude = abs(after_mean - before_mean) / max(before_mean, after_mean, 1.0)
            out_rows.append({
                "entity_type": "ip", "entity_id": ip,
                "change_date": str(dates[bk]) if bk < len(dates) else str(dates[-1]),
                "idx": bk, "series_len": len(series),
                "before_mean": before_mean, "after_mean": after_mean,
                "magnitude": float(magnitude),
            })

    con.close()
    out_rows.sort(key=lambda r: r["magnitude"], reverse=True)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "ip_changepoints.parquet"
    pq.write_table(pa.Table.from_pylist(out_rows, schema=SCHEMA),
                   out_path, compression="zstd", compression_level=3)

    md_lines = [
        "# Per-IP change-point detection",
        "",
        f"{len(out_rows):,} change points detected across {len(top_ips):,} top IPs",
        f"(min {args.min_days} active days, "
        f"mBIC PELT penalty scale={args.penalty_scale}).",
        "",
        "_Penalty is length- and variance-adaptive (mBIC: pen ~ 2 sigma^2 ln n) "
        "rather than a fixed constant — short series get fewer false "
        "positives, long series stop missing real shifts._",
        "",
        "## Top 40 most significant changes",
        "",
        "| src_ip | change_date | before_mean | after_mean | magnitude |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in out_rows[:40]:
        md_lines.append(f"| {r['entity_id']} | {r['change_date']} | "
                        f"{r['before_mean']:.1f} | {r['after_mean']:.1f} | "
                        f"{r['magnitude']:.2f} |")
    (OUT_DIR / "ip_changepoints.md").write_text("\n".join(md_lines) + "\n")
    print(f"[changepoints] wrote {out_path}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top-ips", type=int, default=500,
                    help="Run on the top N IPs by packet count")
    ap.add_argument("--min-days", type=int, default=30,
                    help="Skip IPs active fewer than this many distinct days")
    ap.add_argument("--min-segment", type=int, default=7,
                    help="Min length of a stable segment between change points")
    ap.add_argument("--penalty-scale", type=float, default=1.0,
                    help="Scale factor on the mBIC PELT penalty "
                         "(default 1.0; raise to suppress more change "
                         "points, lower to surface more). Penalty itself "
                         "is length- and variance-adaptive.")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

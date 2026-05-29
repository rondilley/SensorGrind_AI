#!/usr/bin/env python3
"""
longitudinal/cross_modal_lag — time-lagged cross-correlation between
different activity modes.

Builds daily count series for each "mode":
  - one per probe_tag from probesigs (one series per CVE/exploit)
  - one per botnet family from botnetcls
  - one per dropper host (top-N from droppers)
  - one per port (top-N most-targeted)

Then computes pairwise lagged Pearson correlation at lags 0-30 days.
Pairs with strong correlation at non-zero lag suggest a causal/staged
relationship (e.g. dropper family X consistently precedes CVE-Y
probing by L days, or port-N hits surge L days before family-M).

Output: top lagged pairs ranked by max correlation outside lag 0.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib

OUT_DIR = lib.OUTPUT_DIR / "patterns" / "cross_modal_lag"

SCHEMA = pa.schema([
    ("series_a",     pa.string()),
    ("series_b",     pa.string()),
    ("lag_days",     pa.int16()),
    ("correlation",  pa.float32()),
    ("days_overlap", pa.uint16()),
])


def daily_series(con, label: str, sql: str) -> tuple[str, dict]:
    rows = con.execute(sql).fetchall()
    return label, {str(r[0]): int(r[1]) for r in rows}


def to_array(series: dict, dates: list[str]) -> np.ndarray:
    return np.array([series.get(d, 0) for d in dates], dtype=np.float64)


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    print("[lag] building daily series for each mode...", file=sys.stderr)
    series_map: dict[str, dict] = {}

    # Probe tags
    probesigs_path = lib.REPORTS / "probesigs" / "probesigs.parquet"
    if probesigs_path.exists() and probesigs_path.stat().st_size > 0:
        tags = con.execute(f"""
            SELECT DISTINCT probe_tag FROM read_parquet('{probesigs_path}')
            ORDER BY probe_tag
        """).fetchall()
        for (tag,) in tags:
            label, s = daily_series(con, f"probe:{tag}", f"""
                SELECT CAST(i.ts AS DATE) AS d, count(*) AS c
                FROM iocs i
                JOIN read_parquet('{probesigs_path}') p ON i.value = p.uri
                WHERE i.ioc_kind = {lib.IOC_ID['http_uri']}
                  AND p.probe_tag = '{tag}'
                GROUP BY d ORDER BY d
            """)
            series_map[label] = s

    # Botnet families
    botnet_path = lib.REPORTS / "botnetcls" / "botnetcls.parquet"
    if botnet_path.exists() and botnet_path.stat().st_size > 0:
        fams = con.execute(f"""
            SELECT DISTINCT family FROM read_parquet('{botnet_path}')
            WHERE family != '' ORDER BY family
        """).fetchall()
        for (fam,) in fams:
            label, s = daily_series(con, f"botnet:{fam}", f"""
                SELECT CAST(p.ts AS DATE) AS d, count(DISTINCT p.src_ip) AS c
                FROM packets p
                JOIN read_parquet('{botnet_path}') b ON p.payload_sha256 = b.payload_sha256
                WHERE b.family = '{fam}'
                GROUP BY d ORDER BY d
            """)
            series_map[label] = s

    # Top-K ports
    top_ports = con.execute(f"""
        SELECT dst_port, count(*) AS c FROM packets
        WHERE dst_port IS NOT NULL GROUP BY dst_port
        ORDER BY c DESC LIMIT {args.top_ports}
    """).fetchall()
    for port, _ in top_ports:
        label, s = daily_series(con, f"port:{port}", f"""
            SELECT CAST(ts AS DATE) AS d, count(DISTINCT src_ip) AS c
            FROM packets WHERE dst_port = {port}
            GROUP BY d ORDER BY d
        """)
        series_map[label] = s

    con.close()
    print(f"[lag] built {len(series_map):,} daily series", file=sys.stderr)

    # Build a shared date axis as the union of all keys.
    all_dates = sorted({d for s in series_map.values() for d in s})
    if len(all_dates) < args.max_lag + 30:
        print("[lag] not enough days for lag analysis", file=sys.stderr)
        return 0
    arrs = {label: to_array(s, all_dates) for label, s in series_map.items()}

    # STL-decompose each series and use the *residuals* for cross-correlation.
    # Raw daily counts have strong weekly seasonality and long-term trend;
    # Pearson on the raw series produces spurious 7-day "causal" lags that
    # are really weekly cycles.  Multi-AI methodology review flagged this.
    if not args.no_detrend and len(all_dates) >= 28:
        from statsmodels.tsa.seasonal import STL
        print("[lag] STL-detrending each series before correlation...",
              file=sys.stderr)
        detrended: dict[str, np.ndarray] = {}
        for label, arr in arrs.items():
            try:
                stl = STL(arr, period=7, robust=True).fit()
                detrended[label] = arr - stl.trend - stl.seasonal
            except Exception:
                detrended[label] = arr  # fallback: keep raw
        arrs = detrended

    print(f"[lag] computing pairwise lagged correlations "
          f"({len(arrs):,} series, +/-{args.max_lag}d lag)...", file=sys.stderr)
    out_rows: list[dict] = []
    labels = list(arrs.keys())
    for i, a_label in enumerate(labels):
        a = arrs[a_label]
        if a.std() < 1e-6:
            continue
        for j in range(i + 1, len(labels)):
            b_label = labels[j]
            b = arrs[b_label]
            if b.std() < 1e-6:
                continue
            best_corr = 0.0
            best_lag = 0
            for lag in range(-args.max_lag, args.max_lag + 1):
                if lag < 0:
                    a_s = a[-lag:]
                    b_s = b[:len(b) + lag]
                elif lag > 0:
                    a_s = a[:len(a) - lag]
                    b_s = b[lag:]
                else:
                    a_s = a; b_s = b
                if len(a_s) < 30 or a_s.std() < 1e-6 or b_s.std() < 1e-6:
                    continue
                c = float(np.corrcoef(a_s, b_s)[0, 1])
                if abs(c) > abs(best_corr):
                    best_corr = c
                    best_lag = lag
            if abs(best_corr) >= args.min_corr and best_lag != 0:
                out_rows.append({
                    "series_a": a_label, "series_b": b_label,
                    "lag_days": int(best_lag),
                    "correlation": float(best_corr),
                    "days_overlap": int(min(len(a), len(b))),
                })

    out_rows.sort(key=lambda r: abs(r["correlation"]), reverse=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(out_rows, schema=SCHEMA),
                   OUT_DIR / "lag_pairs.parquet",
                   compression="zstd", compression_level=3)

    md_lines = ["# Cross-modal lag correlation", "",
                f"**{len(out_rows):,}** lagged pairs (|corr| >= {args.min_corr}, "
                f"lag != 0, max lag {args.max_lag}d)",
                "",
                "## Top 50 lagged pairs (positive lag = A precedes B)",
                "",
                "| series_a | series_b | lag_days | correlation |",
                "| --- | --- | --- | --- |"]
    for r in out_rows[:50]:
        md_lines.append(f"| {r['series_a']} | {r['series_b']} | "
                        f"{r['lag_days']:+d} | {r['correlation']:+.3f} |")
    (OUT_DIR / "lag_pairs.md").write_text("\n".join(md_lines) + "\n")
    print(f"[lag] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top-ports", type=int, default=20)
    ap.add_argument("--max-lag", type=int, default=21)
    ap.add_argument("--min-corr", type=float, default=0.5)
    ap.add_argument("--no-detrend", action="store_true",
                    help="Skip STL detrending (default: detrend, period=7 days, "
                         "removes weekly seasonality + long-term trend so the "
                         "lag-correlation is on residuals, not raw counts).")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

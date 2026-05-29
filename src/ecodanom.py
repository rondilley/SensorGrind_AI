#!/usr/bin/env python3
"""
ecodanom — ECOD anomaly scoring on per-IP feature vectors.

Uses PyOD's ECOD (Empirical Cumulative Distribution based Outlier
Detection) to find anomalous source IPs — those with unusual
combinations of TTL, window size, port diversity, payload rates,
and timing patterns. ECOD is O(n) and parameter-free.
"""
from __future__ import annotations

import argparse
import sys

import numpy as np
import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("src_ip",        pa.string()),
    ("anomaly_score", pa.float64()),
    ("is_anomaly",    pa.bool_()),
    ("pkt_count",     pa.uint64()),
    ("port_count",    pa.uint32()),
    ("ttl_mode",      pa.uint8()),
    ("syn_pct",       pa.float32()),
    ("payload_pct",   pa.float32()),
    ("day_count",     pa.uint16()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    min_pkts = 10
    print("[ecodanom] building feature vectors...", file=sys.stderr)
    rows = con.execute(f"""
        SELECT src_ip, count(*) AS pkt_count,
               count(DISTINCT dst_port) AS port_count,
               mode(ttl) AS ttl_mode,
               count(*) FILTER (WHERE tcp_flags = 2) * 1.0 / count(*) AS syn_pct,
               count(*) FILTER (WHERE payload_len > 0) * 1.0 / count(*) AS payload_pct,
               count(DISTINCT dt) AS day_count,
               mode(tcp_win) AS win_mode
        FROM packets
        WHERE {where}
        GROUP BY src_ip
        HAVING count(*) >= {min_pkts}
    """).fetchall()
    print(f"[ecodanom] {len(rows):,} IPs with {min_pkts}+ packets", file=sys.stderr)
    con.close()

    ips = [r[0] for r in rows if lib.is_real_external_ip(r[0])]
    features = []
    ip_data = {}
    for r in rows:
        ip = r[0]
        if not lib.is_real_external_ip(ip):
            continue
        vec = [
            float(r[1]),      # pkt_count (log)
            float(r[2]),      # port_count
            float(r[3] or 0), # ttl_mode
            float(r[4] or 0), # syn_pct
            float(r[5] or 0), # payload_pct
            float(r[6]),      # day_count
            float(r[7] or 0), # win_mode
        ]
        features.append(vec)
        ip_data[ip] = r

    X = np.array(features, dtype=np.float64)
    X[:, 0] = np.log1p(X[:, 0])  # log-scale packet count
    X[:, 1] = np.log1p(X[:, 1])  # log-scale port count

    print(f"[ecodanom] running ECOD on {X.shape[0]:,} IPs × {X.shape[1]} features...",
          file=sys.stderr)
    from pyod.models.ecod import ECOD
    clf = ECOD(contamination=0.05)
    clf.fit(X)
    scores = clf.decision_scores_
    labels = clf.labels_

    results: list[dict] = []
    for i, ip in enumerate(ips):
        r = ip_data[ip]
        results.append({
            "src_ip": ip, "anomaly_score": float(scores[i]),
            "is_anomaly": bool(labels[i]), "pkt_count": r[1],
            "port_count": r[2], "ttl_mode": r[3] or 0,
            "syn_pct": float(r[4] or 0), "payload_pct": float(r[5] or 0),
            "day_count": r[6],
        })

    results.sort(key=lambda r: r["anomaly_score"], reverse=True)
    anomaly_count = sum(1 for r in results if r["is_anomaly"])
    top_n = args.limit or 50

    md = f"""## Summary

- **{len(results):,}** IPs scored
- **{anomaly_count:,}** flagged as anomalous (top 5% by ECOD score)

## Top {top_n} most anomalous IPs

"""
    md += lib.markdown_table(results[:top_n],
        columns=["src_ip", "anomaly_score", "pkt_count", "port_count",
                 "ttl_mode", "syn_pct", "payload_pct", "day_count"])

    print(f"[ecodanom] {anomaly_count:,} anomalies detected", file=sys.stderr)
    return lib.Report(name="ecodanom", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[ecodanom] wrote {paths['parquet']}")
    print(f"[ecodanom] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

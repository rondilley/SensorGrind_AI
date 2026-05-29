#!/usr/bin/env python3
"""
clusterxref — cross-reference outputs of all analyzers per source IP.

Joins benignfilter, fingerprint, portscans, campaign, botnetcls,
and timing outputs to build a unified per-IP threat profile. Identifies
IPs flagged by multiple analyzers as higher-confidence threats.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("src_ip",         pa.string()),
    ("signal_count",   pa.uint8()),
    ("signals",        pa.string()),
    ("is_benign",      pa.bool_()),
    ("benign_org",     pa.string()),
    ("is_scanner",     pa.bool_()),
    ("scan_type",      pa.string()),
    ("is_automated",   pa.bool_()),
    ("botnet_family",  pa.string()),
    ("campaign_count", pa.uint16()),
    ("pkt_count",      pa.uint64()),
])


def _load_report(con, name: str, cols: str) -> dict:
    path = lib.REPORTS / name / f"{name}.parquet"
    if not path.exists() or path.stat().st_size == 0:
        return {}
    rows = con.execute(f"SELECT {cols} FROM read_parquet('{path}')").fetchall()
    return {r[0]: r[1:] for r in rows}


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[clusterxref] loading analyzer outputs...", file=sys.stderr)
    benign = _load_report(con, "benignfilter", "src_ip, org")
    scans = _load_report(con, "portscans", "src_ip, scan_type")
    timing_map = _load_report(con, "timing", "src_ip, automated")

    # Campaign: count campaigns per IP
    campaign_path = lib.REPORTS / "campaign" / "campaign.parquet"
    ip_campaigns: dict[str, int] = {}
    if campaign_path.exists() and campaign_path.stat().st_size > 0:
        camp_rows = con.execute(f"""
            SELECT src_ip, count(*) AS campaigns FROM (
                SELECT unnest(string_split(sample_ips, ', ')) AS src_ip
                FROM read_parquet('{campaign_path}')
            ) GROUP BY src_ip
        """).fetchall()
        ip_campaigns = {r[0]: r[1] for r in camp_rows}

    # Botnet: get family per payload, then map to IPs
    botnet_path = lib.REPORTS / "botnetcls" / "botnetcls.parquet"
    ip_botnet: dict[str, str] = {}
    if botnet_path.exists() and botnet_path.stat().st_size > 0:
        try:
            bn_rows = con.execute(f"""
                SELECT DISTINCT p.src_ip, b.family
                FROM read_parquet('{botnet_path}') b
                JOIN packets p ON p.payload_sha256 = b.payload_sha256
                WHERE {where}
            """).fetchall()
            ip_botnet = {r[0]: r[1] for r in bn_rows}
        except Exception:
            pass

    # Get all IPs with packet counts
    print("[clusterxref] building unified profiles...", file=sys.stderr)
    all_ips = con.execute(f"""
        SELECT src_ip, count(*) AS pkt_count FROM packets WHERE {where}
        GROUP BY src_ip HAVING count(*) >= 5
    """).fetchall()
    con.close()

    results: list[dict] = []
    for ip, pkt_count in all_ips:
        if not lib.is_real_external_ip(ip):
            continue

        signals = []
        is_benign = ip in benign
        benign_org = benign.get(ip, ("",))[0] if is_benign else ""
        is_scanner = ip in scans
        scan_type = scans.get(ip, ("",))[0] if is_scanner else ""
        is_automated = bool(timing_map.get(ip, (False,))[0]) if ip in timing_map else False
        botnet_family = ip_botnet.get(ip, "")
        camp_count = ip_campaigns.get(ip, 0)

        if is_benign:
            signals.append(f"benign:{benign_org}")
        if is_scanner:
            signals.append(f"scan:{scan_type}")
        if is_automated:
            signals.append("automated")
        if botnet_family:
            signals.append(f"botnet:{botnet_family}")
        if camp_count > 0:
            signals.append(f"campaigns:{camp_count}")

        if not signals:
            continue

        results.append({
            "src_ip": ip, "signal_count": len(signals),
            "signals": "; ".join(signals),
            "is_benign": is_benign, "benign_org": benign_org,
            "is_scanner": is_scanner, "scan_type": scan_type,
            "is_automated": is_automated, "botnet_family": botnet_family,
            "campaign_count": camp_count, "pkt_count": pkt_count,
        })

    results.sort(key=lambda r: r["signal_count"], reverse=True)
    top_n = args.limit or 50
    multi_signal = sum(1 for r in results if r["signal_count"] >= 2)

    md = f"""## Summary

- **{len(results):,}** IPs with at least one analyzer signal
- **{multi_signal:,}** IPs flagged by 2+ analyzers

## Top {top_n} IPs by signal count

"""
    md += lib.markdown_table(results[:top_n],
        columns=["src_ip", "signal_count", "signals", "pkt_count"])

    return lib.Report(name="clusterxref", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[clusterxref] wrote {paths['parquet']}")
    print(f"[clusterxref] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

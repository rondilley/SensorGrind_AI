#!/usr/bin/env python3
"""
isc_compare - compare local sensor activity to SANS Internet Storm Center.

Fetches public ISC API endpoints, caches the responses, and computes
set-differences vs the local sensor's most-recent activity window.

Endpoints
---------
- https://isc.sans.edu/api/topports?json    (top ports global, last day)
- https://isc.sans.edu/api/sources?json     (top src IPs global, last day)

Comparisons
-----------
1. ports we see that ISC's global top ~100 don't (sensor-specific targeting)
2. ports ISC sees a lot that we see little/none of (gaps in sensor exposure)
3. top src IPs we share with ISC global feed (validates well-known scanners)
4. top src IPs we see that aren't in ISC's top-sources (potentially novel,
   sensor-specific, or low-volume widely-distributed actors)

Output: output/reports/isc_compare/*.parquet + .md  + cached JSON in
        output/isc_cache/

Run with --offline to use only the cached JSON (skip live fetch).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import urllib.request
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


CACHE = lib.OUTPUT_DIR / "isc_cache"
OUT_DIR = lib.REPORTS / "isc_compare"

PORTS_SCHEMA = pa.schema([
    ("port",          pa.uint16()),
    ("isc_records",   pa.uint64()),
    ("isc_targets",   pa.uint32()),
    ("local_packets", pa.uint64()),
    ("local_ips",     pa.uint32()),
    ("status",        pa.string()),
])
IPS_SCHEMA = pa.schema([
    ("src_ip",        pa.string()),
    ("isc_reports",   pa.uint64()),
    ("local_packets", pa.uint64()),
    ("local_ports",   pa.uint32()),
    ("status",        pa.string()),
])


def _fetch_json(url: str, cache_path: Path, force: bool) -> list | dict | None:
    if cache_path.exists() and not force:
        try:
            return json.loads(cache_path.read_text())
        except Exception:
            pass
    if force is False and cache_path.exists():
        return None
    req = urllib.request.Request(url, headers={
        "User-Agent": "SensorGrind_AI/1.0 (research; honeypot longitudinal analysis)",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(data, indent=2))
        return data
    except Exception as e:
        print(f"[isc] fetch failed {url}: {e}", file=sys.stderr)
        return None


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    today = _dt.date.today().isoformat()
    topports = _fetch_json(
        "https://isc.sans.edu/api/topports?json",
        CACHE / f"topports_{today}.json",
        force=not args.offline,
    )
    topips = _fetch_json(
        "https://isc.sans.edu/api/sources?json",
        CACHE / f"sources_{today}.json",
        force=not args.offline,
    )

    # ISC topports returns list of dicts with 'port', 'records', 'targets'
    isc_ports: dict[int, tuple[int, int]] = {}
    if isinstance(topports, list):
        for row in topports:
            try:
                port = int(row.get("port") or row.get("portnumber") or 0)
                rec = int(row.get("records", 0))
                tgt = int(row.get("targets", 0))
                isc_ports[port] = (rec, tgt)
            except Exception:
                continue
    print(f"[isc] {len(isc_ports):,} ports in ISC top list", file=sys.stderr)

    isc_ips: dict[str, int] = {}
    if isinstance(topips, list):
        for row in topips:
            ip = row.get("source") or row.get("ip")
            try:
                isc_ips[str(ip)] = int(row.get("reports", row.get("count", 0)))
            except Exception:
                continue
    print(f"[isc] {len(isc_ips):,} src IPs in ISC sources list", file=sys.stderr)

    # ---- compare to local sensor (recent window) ----
    con = lib.duck(memory_limit="8GB")
    lib.register_views(con)

    max_date = con.execute("SELECT max(ts)::DATE FROM packets").fetchone()[0]
    if max_date is None:
        print("[isc] no local data", file=sys.stderr)
        return 2
    cutoff = max_date - _dt.timedelta(days=args.recent_days)
    print(f"[isc] local window: {cutoff} -> {max_date}", file=sys.stderr)

    print("[isc] local top ports...", file=sys.stderr)
    local_ports = con.execute(f"""
        SELECT dst_port, count(*) AS packets, count(DISTINCT src_ip) AS ips
        FROM packets
        WHERE dst_port IS NOT NULL AND ts >= TIMESTAMP '{cutoff} 00:00:00+00'
        GROUP BY dst_port ORDER BY packets DESC LIMIT 200
    """).fetchall()
    local_port_map = {int(r[0]): (int(r[1]), int(r[2])) for r in local_ports}

    print("[isc] local top src IPs...", file=sys.stderr)
    local_ip_rows = con.execute(f"""
        SELECT src_ip, count(*) AS packets, count(DISTINCT dst_port) AS ports
        FROM packets
        WHERE ts >= TIMESTAMP '{cutoff} 00:00:00+00'
        GROUP BY src_ip ORDER BY packets DESC LIMIT 200
    """).fetchall()
    local_ip_map = {r[0]: (int(r[1]), int(r[2])) for r in local_ip_rows}
    con.close()

    # ---- compose port comparison rows ----
    port_rows: list[dict] = []
    isc_set = set(isc_ports.keys())
    local_set = set(local_port_map.keys())
    for p in sorted(local_set | isc_set):
        rec, tgt = isc_ports.get(p, (0, 0))
        lp, li = local_port_map.get(p, (0, 0))
        if p in isc_set and p in local_set:
            status = "shared"
        elif p in local_set:
            status = "local_only"
        else:
            status = "isc_only"
        port_rows.append({
            "port": p,
            "isc_records": rec, "isc_targets": tgt,
            "local_packets": lp, "local_ips": li,
            "status": status,
        })
    pq.write_table(pa.Table.from_pylist(port_rows, schema=PORTS_SCHEMA),
                   OUT_DIR / "port_compare.parquet",
                   compression="zstd", compression_level=3)

    # ---- ip comparison rows ----
    ip_rows: list[dict] = []
    all_ips = set(isc_ips.keys()) | set(local_ip_map.keys())
    for ip in all_ips:
        irep = isc_ips.get(ip, 0)
        lpk, lprt = local_ip_map.get(ip, (0, 0))
        if ip in isc_ips and ip in local_ip_map:
            status = "shared"
        elif ip in local_ip_map:
            status = "local_only"
        else:
            status = "isc_only"
        ip_rows.append({
            "src_ip": ip, "isc_reports": irep,
            "local_packets": lpk, "local_ports": lprt,
            "status": status,
        })
    pq.write_table(pa.Table.from_pylist(ip_rows, schema=IPS_SCHEMA),
                   OUT_DIR / "src_compare.parquet",
                   compression="zstd", compression_level=3)

    # ---- markdown ----
    md = ["# isc_compare - local vs SANS Internet Storm Center", "",
          f"_ISC snapshot fetched: `{today}`.  Local window: "
          f"{cutoff} -> {max_date} ({args.recent_days}d).  "
          "Port lists are limited to the top-200 of each side._", ""]

    md.append("## Local-only top ports (in local top-200, NOT in ISC top list)")
    md.append("")
    md.append("_Targets that matter for this sensor more than globally - "
              "either sensor-specific exposure or scanning patterns that "
              "haven't yet bubbled up to the ISC aggregate._")
    md.append("")
    md.append("| port | local_packets | local_ips |")
    md.append("| --- | --- | --- |")
    for r in sorted([r for r in port_rows if r["status"] == "local_only"],
                    key=lambda r: -r["local_packets"])[:30]:
        md.append(f"| {r['port']} | {r['local_packets']:,} | {r['local_ips']:,} |")

    md.extend(["", "## ISC-only top ports (in ISC top list, NOT in local top-200)",
               "",
               "_Things the wider internet is being hit with that this sensor "
               "is missing - possibly because the sensor doesn't emulate the "
               "right service, possibly because the campaign hasn't reached "
               "this sensor's address space._",
               "",
               "| port | isc_records | isc_targets |",
               "| --- | --- | --- |"])
    for r in sorted([r for r in port_rows if r["status"] == "isc_only"],
                    key=lambda r: -r["isc_records"])[:30]:
        md.append(f"| {r['port']} | {r['isc_records']:,} | {r['isc_targets']:,} |")

    md.extend(["", "## Shared top ports",
               "",
               "_Targets that matter both locally and globally - the "
               "well-validated background of internet scanning activity._",
               "",
               "| port | isc_records | local_packets | local_ips |",
               "| --- | --- | --- | --- |"])
    for r in sorted([r for r in port_rows if r["status"] == "shared"],
                    key=lambda r: -r["local_packets"])[:30]:
        md.append(f"| {r['port']} | {r['isc_records']:,} | "
                  f"{r['local_packets']:,} | {r['local_ips']:,} |")

    md.extend(["", "## Shared top source IPs (ISC + local)",
               "",
               "_IPs the sensor saw recently that ISC's global feed also "
               "flagged - confirms widely-deployed scanners and validates "
               "local benignfilter classifications._",
               "",
               "| src_ip | isc_reports | local_packets | local_ports |",
               "| --- | --- | --- | --- |"])
    for r in sorted([r for r in ip_rows if r["status"] == "shared"],
                    key=lambda r: -r["isc_reports"])[:30]:
        md.append(f"| {r['src_ip']} | {r['isc_reports']:,} | "
                  f"{r['local_packets']:,} | {r['local_ports']:,} |")

    (OUT_DIR / "isc_compare.md").write_text("\n".join(md) + "\n")
    print(f"[isc] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--recent-days", type=int, default=7,
                    help="Local activity window to compare (default 7d)")
    ap.add_argument("--offline", action="store_true",
                    help="Skip live ISC fetch; only use cached JSON")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

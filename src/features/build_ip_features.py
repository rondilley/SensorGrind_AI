#!/usr/bin/env python3
"""
features/build_ip_features — per-IP feature vector daily snapshot.

Produces a single Parquet snapshot of feature vectors for every
source IP in the corpus (or in a date window). Features come from
four sources:

  1. packets aggregate: volumetric, temporal, protocol, TCP behavior
  2. iocs aggregate: distinct UAs / URIs / SSH banners / hashes
  3. l7_events aggregate: per-protocol event counts
  4. existing analyzer outputs (benignfilter, ecodanom, portscans, ...)

These vectors are the substrate for: ML threat classification,
HDBSCAN campaign clustering, ECOD-style anomaly detection,
risk scoring, and pattern mining.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1

SCHEMA = pa.schema([
    ("src_ip",            pa.string()),
    # volumetric
    ("pkt_count",         pa.uint64()),
    ("byte_count",        pa.uint64()),
    ("day_count",         pa.uint16()),
    ("first_seen",        pa.timestamp("us", tz="UTC")),
    ("last_seen",         pa.timestamp("us", tz="UTC")),
    ("span_days",         pa.float32()),
    ("pkts_per_active_day", pa.float32()),
    # protocol mix
    ("pct_tcp",           pa.float32()),
    ("pct_udp",           pa.float32()),
    ("pct_icmp",          pa.float32()),
    # TCP behavior
    ("pct_syn_only",      pa.float32()),
    ("ttl_mode",          pa.uint8()),
    ("tcp_win_mode",      pa.uint32()),
    # port targeting
    ("port_count",        pa.uint32()),
    ("top_port",          pa.uint16()),
    ("port_diversity",    pa.float32()),  # port_count / pkt_count
    # payload behavior
    ("pct_with_payload",  pa.float32()),
    ("distinct_payloads", pa.uint32()),
    ("avg_payload_len",   pa.float32()),
    # L7 mix
    ("l7_dominant",       pa.string()),
    ("l7_event_count",    pa.uint32()),
    ("l7_distinct_protos", pa.uint8()),
    ("n_http_events",     pa.uint32()),
    ("n_tls_events",      pa.uint32()),
    ("n_ssh_events",      pa.uint32()),
    ("n_rdp_events",      pa.uint32()),
    # IOC behavior
    ("ioc_count",         pa.uint32()),
    ("distinct_uas",      pa.uint16()),
    ("distinct_uris",     pa.uint16()),
    ("distinct_hashes",   pa.uint16()),
    ("distinct_creds",    pa.uint16()),
    ("distinct_msts",     pa.uint16()),
    # geo/asn
    ("country_iso",       pa.string()),
    ("asn",               pa.uint32()),
    ("asn_org",           pa.string()),
    # existing analyzer signals (bootstrap labels)
    ("benign_org",        pa.string()),
    ("scan_type",         pa.string()),
    ("anomaly_score",     pa.float64()),
    ("is_automated",      pa.bool_()),
    ("burstiness_cv",     pa.float32()),
    ("campaign_count",    pa.uint16()),
    ("botnet_family",     pa.string()),
])


def _read_join(con, name: str, cols: list[str]) -> dict:
    """Load a report's parquet as {src_ip: tuple(cols)} for fast joining."""
    p = lib.REPORTS / name / f"{name}.parquet"
    if not p.exists() or p.stat().st_size == 0:
        return {}
    cols_sql = ", ".join(cols)
    rows = con.execute(f"SELECT src_ip, {cols_sql} FROM read_parquet('{p}')").fetchall()
    return {r[0]: r[1:] for r in rows}


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    # ---- Pass 1: packet-level aggregates per IP -------------------
    print("[ip_features] aggregating per-IP packet stats...", file=sys.stderr)
    pkt_rows = con.execute(f"""
        SELECT
            src_ip,
            count(*)                              AS pkt_count,
            sum(pkt_len)                          AS byte_count,
            count(DISTINCT dt)                    AS day_count,
            min(ts)                               AS first_seen,
            max(ts)                               AS last_seen,
            count(*) FILTER (WHERE proto = 6)     AS n_tcp,
            count(*) FILTER (WHERE proto = 17)    AS n_udp,
            count(*) FILTER (WHERE proto = 1)     AS n_icmp,
            count(*) FILTER (WHERE tcp_flags = 2) AS n_syn,
            mode(ttl)                             AS ttl_mode,
            mode(tcp_win)                         AS tcp_win_mode,
            count(DISTINCT dst_port)              AS port_count,
            mode(dst_port)                        AS top_port,
            count(*) FILTER (WHERE payload_len > 0)  AS n_with_payload,
            count(DISTINCT payload_sha256)        AS distinct_payloads,
            avg(payload_len) FILTER (WHERE payload_len > 0) AS avg_payload_len,
            mode(l7_proto)                        AS l7_mode
        FROM packets
        WHERE {where}
        GROUP BY src_ip
    """).fetchall()
    print(f"[ip_features] {len(pkt_rows):,} IPs from packets", file=sys.stderr)

    # ---- Pass 2: L7 event counts ---------------------------------
    print("[ip_features] aggregating l7_events per IP...", file=sys.stderr)
    l7_rows = con.execute(f"""
        SELECT src_ip,
               count(*) AS l7_total,
               count(DISTINCT l7_proto) AS l7_distinct,
               count(*) FILTER (WHERE l7_proto = {lib.L7_ID['http']}) AS n_http,
               count(*) FILTER (WHERE l7_proto = {lib.L7_ID['tls']})  AS n_tls,
               count(*) FILTER (WHERE l7_proto = {lib.L7_ID['ssh']})  AS n_ssh,
               count(*) FILTER (WHERE l7_proto = {lib.L7_ID['rdp']})  AS n_rdp
        FROM l7_events WHERE {where} GROUP BY src_ip
    """).fetchall()
    l7_map = {r[0]: r[1:] for r in l7_rows}

    # ---- Pass 3: IOC behavior -----------------------------------
    print("[ip_features] aggregating iocs per IP...", file=sys.stderr)
    ioc_rows = con.execute(f"""
        SELECT src_ip,
               count(*) AS n_iocs,
               count(DISTINCT value) FILTER (WHERE ioc_kind = {lib.IOC_ID['user_agent']}) AS d_ua,
               count(DISTINCT value) FILTER (WHERE ioc_kind = {lib.IOC_ID['http_uri']})   AS d_uri,
               count(DISTINCT value) FILTER (WHERE ioc_kind = {lib.IOC_ID['file_hash']})  AS d_hash,
               count(DISTINCT value) FILTER (WHERE ioc_kind = {lib.IOC_ID['cred']})       AS d_cred,
               count(DISTINCT value) FILTER (WHERE ioc_kind = {lib.IOC_ID['mstshash']})   AS d_msts
        FROM iocs WHERE {where} GROUP BY src_ip
    """).fetchall()
    ioc_map = {r[0]: r[1:] for r in ioc_rows}

    # ---- Pass 4: bootstrap labels from existing reports ----------
    print("[ip_features] joining existing analyzer outputs...", file=sys.stderr)
    benign_map = _read_join(con, "benignfilter", ["org"])
    portscan_map = _read_join(con, "portscans", ["scan_type"])
    anomaly_map = _read_join(con, "ecodanom", ["anomaly_score"])
    timing_map = _read_join(con, "timing", ["automated", "burstiness_cv"])

    # Campaign count per IP — derived from clusterxref since campaign
    # output stores sample_ips lists, not per-IP rows.
    xref_path = lib.REPORTS / "clusterxref" / "clusterxref.parquet"
    xref_map = {}
    if xref_path.exists() and xref_path.stat().st_size > 0:
        rows = con.execute(f"SELECT src_ip, campaign_count, botnet_family FROM read_parquet('{xref_path}')").fetchall()
        xref_map = {r[0]: (r[1], r[2]) for r in rows}

    # GeoLite lookups
    geo = lib.GeoLookup()

    # ---- Assemble per-IP feature rows ----------------------------
    print("[ip_features] assembling feature vectors...", file=sys.stderr)
    out: list[dict] = []
    for r in pkt_rows:
        ip = r[0]
        if not lib.is_real_external_ip(ip):
            continue
        pkt = r[1]; bts = r[2] or 0; days = r[3]
        first = r[4]; last = r[5]
        n_tcp = r[6]; n_udp = r[7]; n_icmp = r[8]; n_syn = r[9]
        ttl_mode = r[10] or 0; win_mode = r[11] or 0
        port_count = r[12]; top_port = r[13]
        n_with_payload = r[14]; distinct_payloads = r[15]
        avg_payload_len = float(r[16] or 0)
        l7_mode = r[17]

        l7 = l7_map.get(ip, (0, 0, 0, 0, 0, 0))
        ioc = ioc_map.get(ip, (0, 0, 0, 0, 0, 0))
        benign_org = benign_map.get(ip, ("",))[0] or ""
        scan_type = portscan_map.get(ip, ("",))[0] or ""
        anomaly = float(anomaly_map.get(ip, (0.0,))[0] or 0.0)
        timing_rec = timing_map.get(ip, (False, 0.0))
        is_auto = bool(timing_rec[0]) if timing_rec[0] is not None else False
        burst_cv = float(timing_rec[1] or 0.0)
        xref = xref_map.get(ip, (0, ""))
        camp_count = int(xref[0] or 0)
        botnet_family = xref[1] or ""

        geo_rec = geo.lookup(ip)
        span_seconds = (last - first).total_seconds() if first and last else 0
        span_days = span_seconds / 86400.0

        out.append({
            "src_ip": ip,
            "pkt_count": pkt, "byte_count": int(bts), "day_count": days,
            "first_seen": first, "last_seen": last, "span_days": float(span_days),
            "pkts_per_active_day": pkt / days if days else 0.0,
            "pct_tcp": n_tcp / pkt, "pct_udp": n_udp / pkt, "pct_icmp": n_icmp / pkt,
            "pct_syn_only": n_syn / pkt,
            "ttl_mode": int(ttl_mode), "tcp_win_mode": int(win_mode),
            "port_count": port_count, "top_port": top_port,
            "port_diversity": port_count / pkt if pkt else 0.0,
            "pct_with_payload": n_with_payload / pkt,
            "distinct_payloads": distinct_payloads or 0,
            "avg_payload_len": avg_payload_len,
            "l7_dominant": lib.L7_NAME.get(l7_mode, "unknown"),
            "l7_event_count": l7[0], "l7_distinct_protos": l7[1],
            "n_http_events": l7[2], "n_tls_events": l7[3],
            "n_ssh_events": l7[4], "n_rdp_events": l7[5],
            "ioc_count": ioc[0],
            "distinct_uas": min(ioc[1], 65535), "distinct_uris": min(ioc[2], 65535),
            "distinct_hashes": min(ioc[3], 65535), "distinct_creds": min(ioc[4], 65535),
            "distinct_msts": min(ioc[5], 65535),
            "country_iso": geo_rec.country_iso or "", "asn": geo_rec.asn or 0,
            "asn_org": geo_rec.asn_org or "",
            "benign_org": benign_org, "scan_type": scan_type,
            "anomaly_score": anomaly, "is_automated": is_auto,
            "burstiness_cv": burst_cv, "campaign_count": camp_count,
            "botnet_family": botnet_family,
        })

    geo.close()
    con.close()

    snap_date = lib.parse_date_arg(args.until) or _dt.date.today()
    fs = sf.FeatureSet(entity="ip", version=FEATURE_VERSION, snapshot_date=snap_date)
    table = pa.Table.from_pylist(out, schema=SCHEMA)
    path = sf.write_snapshot(fs, table, manifest={
        "source": "src/features/build_ip_features.py",
        "since": args.since, "until": args.until,
    })
    print(f"[ip_features] wrote {len(out):,} feature vectors -> {path}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

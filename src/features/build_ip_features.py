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
import os
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


# How many result rows DuckDB hands us per Arrow batch.  Memory is bounded
# by one batch's worth of rows, not the whole corpus.
BATCH_ROWS = 50_000
PROGRESS_EVERY = 250_000

# The four columns we can't compute in pure SQL: l7_dominant is a name
# mapping, the geo columns come from the MaxMind mmdbs.  Everything else is
# produced by build_feature_sql() and carried straight through.
_SQL_EXTRA_COL = "l7_mode"  # temporary int carried out of SQL, mapped below


def _mem_available_mb() -> int | None:
    """System MemAvailable in MiB, or None if /proc isn't readable."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError):
        return None
    return None


def _auto_buckets() -> int:
    """How many IP-hash buckets to slide over.  More buckets = fewer IP
    groups resident per window = lower peak RAM (at the cost of re-scanning
    the date-partitioned packets once per bucket).  Override with
    SG_FEAT_BUCKETS; otherwise scale to available RAM."""
    env = os.environ.get("SG_FEAT_BUCKETS")
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    avail = _mem_available_mb()
    if avail is None:
        return 1
    if avail < 8_000:
        return 16
    if avail < 16_000:
        return 8
    if avail < 32_000:
        return 4
    return 1


def build_feature_sql(where: str, bucket: tuple[int, int] | None = None,
                      packets_from: str = "packets",
                      l7_from: str = "l7_events", ioc_from: str = "iocs",
                      restrict_to_pkt: bool = False) -> str:
    """Build the streaming aggregation+join query for one IP window.

    All per-IP aggregation and the bootstrap-label joins happen inside
    DuckDB; the result streams out one batch at a time.  Reports that don't
    exist yet (first run) are simply not joined and their columns default.

    Two windowing modes, both keeping every IP's full history together so
    per-IP aggregates (incl. exact cross-time distinct counts) are correct
    from one bounded window:

    * Clustered (preferred): ``packets_from`` is one ASN-bucket of the
      clustered dataset and ``restrict_to_pkt=True`` scopes l7/ioc to that
      bucket's IPs.  Each window reads only its own files.
    * Raw fallback: ``packets_from='packets'`` with ``bucket=(k, n)`` hashes
      src_ip into n buckets (applied to all three tables).
    """
    # pkt_pred restricts the packets scan; ev_pred restricts the l7/ioc scans.
    pkt_pred = ""
    ev_pred = ""
    if restrict_to_pkt:
        # Clustered path: packets_from is already one ASN-bucket file (a
        # complete set of IPs), so l7/ioc only need that bucket's IPs.
        ev_pred = " AND src_ip IN (SELECT src_ip FROM pkt)"
    elif bucket is not None:
        # Raw path: hash(src_ip) into n buckets, keep bucket k -- applied to
        # all three tables so the same IPs are processed together.
        k, n = bucket
        bp = f" AND (hash(src_ip) % {n}) = {k}"
        pkt_pred = ev_pred = bp

    joins: list[str] = []
    extra: list[str] = []

    def add_report(name: str, alias: str,
                   colmap: list[tuple[str, str, str]]) -> None:
        p = lib.REPORTS / name / f"{name}.parquet"
        if p.exists() and p.stat().st_size > 0:
            cols = ", ".join(["src_ip"] + [src for _, src, _ in colmap])
            joins.append(
                f"LEFT JOIN (SELECT {cols} FROM read_parquet('{p}')) {alias} "
                f"ON {alias}.src_ip = p.src_ip")
            for out_name, src, dflt in colmap:
                extra.append(f"coalesce({alias}.{src}, {dflt}) AS {out_name}")
        else:
            for out_name, src, dflt in colmap:
                extra.append(f"{dflt} AS {out_name}")

    add_report("benignfilter", "b", [("benign_org", "org", "''")])
    add_report("portscans", "ps", [("scan_type", "scan_type", "''")])
    add_report("ecodanom", "an", [("anomaly_score", "anomaly_score", "0.0")])
    add_report("timing", "tm", [("is_automated", "automated", "FALSE"),
                                ("burstiness_cv", "burstiness_cv", "0.0")])
    add_report("clusterxref", "cx", [("campaign_count", "campaign_count", "0"),
                                     ("botnet_family", "botnet_family", "''")])
    extra_sql = ",\n            ".join(extra)
    joins_sql = "\n        ".join(joins)

    http, tls = lib.L7_ID["http"], lib.L7_ID["tls"]
    ssh, rdp = lib.L7_ID["ssh"], lib.L7_ID["rdp"]
    ua, uri = lib.IOC_ID["user_agent"], lib.IOC_ID["http_uri"]
    fh, cr, ms = (lib.IOC_ID["file_hash"], lib.IOC_ID["cred"],
                  lib.IOC_ID["mstshash"])

    def det_mode(hist_col: str, alias: str) -> str:
        # Deterministic mode from a histogram() count map: the key with the
        # highest count, smallest key on a tie.  Reproducible run-to-run,
        # unlike plain mode(), and memory-bounded/spillable unlike the
        # ordered-set mode() WITHIN GROUP.
        return (f"coalesce((SELECT k FROM ("
                f"SELECT unnest(map_keys(p.{hist_col})) k, "
                f"unnest(map_values(p.{hist_col})) v) "
                f"ORDER BY v DESC, k ASC LIMIT 1), 0) AS {alias}")

    ttl_mode_sql = det_mode("h_ttl", "ttl_mode")
    win_mode_sql = det_mode("h_win", "tcp_win_mode")
    top_port_sql = det_mode("h_port", "top_port")
    l7_mode_sql = det_mode("h_l7", "l7_mode")

    return f"""
    WITH pkt AS (
        SELECT src_ip,
            count(*)                                AS pkt_count,
            coalesce(sum(pkt_len), 0)               AS byte_count,
            count(DISTINCT dt)                      AS day_count,
            min(ts)                                 AS first_seen,
            max(ts)                                 AS last_seen,
            count(*) FILTER (WHERE proto = 6)       AS n_tcp,
            count(*) FILTER (WHERE proto = 17)      AS n_udp,
            count(*) FILTER (WHERE proto = 1)       AS n_icmp,
            count(*) FILTER (WHERE tcp_flags = 2)   AS n_syn,
            -- histogram() = bounded, spillable per-group count map; the
            -- deterministic mode (max count, smallest value on tie) is
            -- extracted from it in the outer SELECT (see det_mode()).
            histogram(ttl)                          AS h_ttl,
            histogram(tcp_win)                      AS h_win,
            count(DISTINCT dst_port)                AS port_count,
            histogram(dst_port)                     AS h_port,
            count(*) FILTER (WHERE payload_len > 0) AS n_with_payload,
            count(DISTINCT payload_sha256)          AS distinct_payloads,
            coalesce(avg(payload_len) FILTER (WHERE payload_len > 0), 0)
                                                    AS avg_payload_len,
            histogram(l7_proto)                     AS h_l7
        FROM {packets_from} WHERE {where}{pkt_pred} GROUP BY src_ip
    ),
    l7 AS (
        SELECT src_ip,
            count(*)                                   AS l7_total,
            count(DISTINCT l7_proto)                   AS l7_distinct,
            count(*) FILTER (WHERE l7_proto = {http})  AS n_http,
            count(*) FILTER (WHERE l7_proto = {tls})   AS n_tls,
            count(*) FILTER (WHERE l7_proto = {ssh})   AS n_ssh,
            count(*) FILTER (WHERE l7_proto = {rdp})   AS n_rdp
        FROM {l7_from} WHERE {where}{ev_pred} GROUP BY src_ip
    ),
    ioc AS (
        SELECT src_ip,
            count(*)                                                  AS n_iocs,
            count(DISTINCT value) FILTER (WHERE ioc_kind = {ua})  AS d_ua,
            count(DISTINCT value) FILTER (WHERE ioc_kind = {uri}) AS d_uri,
            count(DISTINCT value) FILTER (WHERE ioc_kind = {fh})  AS d_hash,
            count(DISTINCT value) FILTER (WHERE ioc_kind = {cr})  AS d_cred,
            count(DISTINCT value) FILTER (WHERE ioc_kind = {ms})  AS d_msts
        FROM {ioc_from} WHERE {where}{ev_pred} GROUP BY src_ip
    )
    SELECT
        p.src_ip,
        p.pkt_count, p.byte_count, p.day_count,
        p.first_seen, p.last_seen,
        (epoch(p.last_seen) - epoch(p.first_seen)) / 86400.0 AS span_days,
        CASE WHEN p.day_count > 0
             THEN p.pkt_count::DOUBLE / p.day_count ELSE 0 END
                                                          AS pkts_per_active_day,
        p.n_tcp::DOUBLE  / p.pkt_count                    AS pct_tcp,
        p.n_udp::DOUBLE  / p.pkt_count                    AS pct_udp,
        p.n_icmp::DOUBLE / p.pkt_count                    AS pct_icmp,
        p.n_syn::DOUBLE  / p.pkt_count                    AS pct_syn_only,
        {ttl_mode_sql}, {win_mode_sql},
        p.port_count, {top_port_sql},
        CASE WHEN p.pkt_count > 0
             THEN p.port_count::DOUBLE / p.pkt_count ELSE 0 END
                                                          AS port_diversity,
        p.n_with_payload::DOUBLE / p.pkt_count            AS pct_with_payload,
        coalesce(p.distinct_payloads, 0)                  AS distinct_payloads,
        p.avg_payload_len,
        {l7_mode_sql},
        coalesce(l7.l7_total, 0)                          AS l7_event_count,
        coalesce(l7.l7_distinct, 0)                       AS l7_distinct_protos,
        coalesce(l7.n_http, 0)                            AS n_http_events,
        coalesce(l7.n_tls, 0)                             AS n_tls_events,
        coalesce(l7.n_ssh, 0)                             AS n_ssh_events,
        coalesce(l7.n_rdp, 0)                             AS n_rdp_events,
        coalesce(ioc.n_iocs, 0)                           AS ioc_count,
        least(coalesce(ioc.d_ua,   0), 65535)             AS distinct_uas,
        least(coalesce(ioc.d_uri,  0), 65535)             AS distinct_uris,
        least(coalesce(ioc.d_hash, 0), 65535)             AS distinct_hashes,
        least(coalesce(ioc.d_cred, 0), 65535)             AS distinct_creds,
        least(coalesce(ioc.d_msts, 0), 65535)             AS distinct_msts,
        {extra_sql}
    FROM pkt p
        LEFT JOIN l7  ON l7.src_ip  = p.src_ip
        LEFT JOIN ioc ON ioc.src_ip = p.src_ip
        {joins_sql}
    """


def transform_batch(batch, geo) -> pa.Table:
    """Enrich one Arrow batch: drop bogon/self IPs, add geo + l7 name, and
    coerce to SCHEMA.  Peak memory is a single batch."""
    import pyarrow.compute as pc

    def _coerce(col, field):
        t = field.type
        if (pa.types.is_timestamp(t) and t.tz is not None
                and getattr(col.type, "tz", None) is None):
            col = pc.assume_timezone(col, t.tz)
        return col.cast(t, safe=False)

    tbl = pa.Table.from_batches([batch])
    ips_all = tbl.column("src_ip").to_pylist()
    mask = pa.array([lib.is_real_external_ip(ip) for ip in ips_all],
                    type=pa.bool_())
    tbl = tbl.filter(mask)
    if tbl.num_rows == 0:
        return pa.table({f.name: pa.array([], type=f.type) for f in SCHEMA},
                        schema=SCHEMA)

    ips = tbl.column("src_ip").to_pylist()
    l7_modes = tbl.column(_SQL_EXTRA_COL).to_pylist()
    geo_recs = [geo.lookup(ip) for ip in ips]
    enriched = {
        "l7_dominant": pa.array([lib.L7_NAME.get(m or 0, "unknown")
                                 for m in l7_modes], pa.string()),
        "country_iso": pa.array([g.country_iso or "" for g in geo_recs],
                                pa.string()),
        "asn":         pa.array([int(g.asn or 0) for g in geo_recs],
                                pa.uint32()),
        "asn_org":     pa.array([g.asn_org or "" for g in geo_recs],
                                pa.string()),
    }
    src = {name: tbl.column(name) for name in tbl.schema.names
           if name != _SQL_EXTRA_COL}
    src.update(enriched)
    return pa.table({f.name: _coerce(src[f.name], f) for f in SCHEMA},
                    schema=SCHEMA)


def run(args: argparse.Namespace) -> int:
    con = lib.duck()
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[ip_features] streaming per-IP feature build "
          "(DuckDB aggregate+join -> parquet)...", file=sys.stderr)
    geo = lib.GeoLookup()
    snap_date = lib.parse_date_arg(args.until) or _dt.date.today()
    fs = sf.FeatureSet(entity="ip", version=FEATURE_VERSION,
                       snapshot_date=snap_date)

    # Prefer the ASN-clustered packets (each bucket = whole ASNs/CIDRs/IPs,
    # so a window reads only its own files).  Fall back to hash(src_ip)
    # bucketing over the raw date-partitioned packets when it isn't built.
    clustered = lib.clustered_buckets()
    if clustered:
        # If l7_events/iocs are clustered too, read the matching bucket
        # directly (bounded); else fall back to the raw views scoped to the
        # bucket's IPs.
        l7_clustered = lib.has_clustered(lib.L7_CLUSTERED)
        ioc_clustered = lib.has_clustered(lib.IOCS_CLUSTERED)
        windows = []
        for k in clustered:
            pf = f"read_parquet('{lib.PACKETS_CLUSTERED}/bkt={k}/*.parquet')"
            if l7_clustered and ioc_clustered:
                l7f = f"read_parquet('{lib.L7_CLUSTERED}/bkt={k}/*.parquet')"
                iocf = f"read_parquet('{lib.IOCS_CLUSTERED}/bkt={k}/*.parquet')"
                sql = build_feature_sql(where, packets_from=pf,
                                        l7_from=l7f, ioc_from=iocf,
                                        restrict_to_pkt=False)
            else:
                sql = build_feature_sql(where, packets_from=pf,
                                        restrict_to_pkt=True)
            windows.append((sql, f"asn-bucket {k}"))
        extra = ("packets+l7+iocs" if (l7_clustered and ioc_clustered)
                 else "packets (l7/iocs raw)")
        print(f"[ip_features] sliding over {len(clustered)} clustered "
              f"asn-bucket(s) [{extra}]", file=sys.stderr)
    else:
        n = _auto_buckets()
        windows = [
            (build_feature_sql(where, (k, n) if n > 1 else None),
             f"hash-bucket {k + 1}/{n}")
            for k in range(n)
        ]
        print(f"[ip_features] sliding over {n} IP-hash bucket(s) over raw "
              f"packets (clustered dataset not built)", file=sys.stderr)

    def batches():
        written = 0
        last_logged = 0
        for sql, label in windows:
            reader = con.execute(sql).fetch_record_batch(BATCH_ROWS)
            for batch in reader:
                tbl = transform_batch(batch, geo)
                written += tbl.num_rows
                if written - last_logged >= PROGRESS_EVERY:
                    print(f"[ip_features]   {written:,} feature vectors "
                          f"written...", file=sys.stderr)
                    last_logged = written
                yield tbl
            if len(windows) > 1:
                print(f"[ip_features]   {label} done ({written:,} so far)",
                      file=sys.stderr)

    path, row_count = sf.write_snapshot_stream(fs, SCHEMA, batches(), manifest={
        "source": "src/features/build_ip_features.py",
        "since": args.since, "until": args.until,
    })
    geo.close()
    con.close()
    print(f"[ip_features] wrote {row_count:,} feature vectors -> {path}",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

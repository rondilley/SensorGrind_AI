#!/usr/bin/env python3
"""
cluster_packets — derived packets/l7_events/iocs datasets clustered by
source ASN / CIDR / IP.

The raw packets parquet is partitioned by DATE, so every source IP's history
is scattered across hundreds of daily files.  That forces per-IP / per-ASN /
per-CIDR analysis to either hold ~1M groups in RAM at once or rescan the whole
corpus.

This stage reads the raw packets, enriches each row with the source ASN and
/24 CIDR (from GeoLite), and writes a DERIVED, clustered copy:

    output/parquet/packets_clustered/bkt=K/*.parquet   (+ asn, cidr columns)

bucketed by ``hash(asn) % N`` and sorted within each bucket by
(asn, cidr, src_ip).  Because an IP belongs to one ASN and a /24 sits within
one ASN, this co-locates every ASN, CIDR, and IP's full history in one bounded
bucket -- so consumers read a small, prunable window instead of the scattered
whole.  Parquet row-group statistics on the sort key give ASN/CIDR/IP
predicate pruning without a directory per value (which 996k IPs would explode).

Raw packets stay untouched/immutable; regenerate this whenever the raw data or
the GeoLite db changes.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import shutil
import sys
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib

DEFAULT_BUCKETS = 128


def _cidr_of(ip: str) -> str:
    """The /24 (IPv4) or /64 (IPv6) network containing ``ip``, as a string."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def build_ip_map(con, where: str) -> Path:
    """Map distinct src_ip -> (asn, cidr) via GeoLite, written to a temp
    parquet for DuckDB to join against.  Built from the union of src_ips
    across packets, l7_events and iocs so every clustered table shares one
    consistent ASN/CIDR/bucket assignment.  Bounded by distinct IPs (~1M)."""
    ips = [r[0] for r in con.execute(f"""
        SELECT DISTINCT src_ip FROM (
            SELECT src_ip FROM packets   WHERE {where}
            UNION SELECT src_ip FROM l7_events WHERE {where}
            UNION SELECT src_ip FROM iocs      WHERE {where}
        )""").fetchall()]
    geo = lib.GeoLookup()
    src, asn, cidr = [], [], []
    for ip in ips:
        if not ip:
            continue
        src.append(ip)
        asn.append(int(geo.lookup(ip).asn or 0))
        cidr.append(_cidr_of(ip))
    geo.close()
    tbl = pa.table({
        "src_ip": pa.array(src, pa.string()),
        "asn":    pa.array(asn, pa.int64()),
        "cidr":   pa.array(cidr, pa.string()),
    })
    tmp = lib.PARQUET / "_ip_asn_map.parquet"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(tbl, tmp, compression="zstd")
    print(f"[cluster] mapped {len(src):,} distinct IPs -> asn/cidr",
          file=sys.stderr)
    return tmp


def cluster_table(con, src_view: str, out_dir: Path, n: int,
                  where: str) -> None:
    """Write one clustered table: join the shared asn/cidr map, sort by
    (asn, cidr, src_ip), and write partitioned by hash(asn) bucket.  The sort
    spills to temp_directory (lib.duck sets one) so RAM stays bounded."""
    print(f"[cluster] {src_view} -> {n} asn-bucket(s), "
          f"sorted by (asn, cidr, src_ip)...", file=sys.stderr)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    con.execute(f"""
        COPY (
            SELECT t.*, m.asn, m.cidr, (hash(m.asn) % {n})::INT AS bkt
            FROM {src_view} t
            JOIN ip_map m USING (src_ip)
            WHERE {where}
            ORDER BY bkt, m.asn, m.cidr, t.src_ip
        ) TO '{out_dir}'
        (FORMAT parquet, PARTITION_BY (bkt),
         COMPRESSION zstd, OVERWRITE_OR_IGNORE)
    """)
    print(f"[cluster]   {src_view} done in {time.time() - t0:.1f}s -> {out_dir}",
          file=sys.stderr)


def run(args: argparse.Namespace) -> int:
    con = lib.duck()
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))
    n = max(1, args.buckets)

    ip_map = build_ip_map(con, where)
    con.execute(
        f"CREATE VIEW ip_map AS SELECT * FROM read_parquet('{ip_map}')")

    # Same bucketing for all three tables (one shared ip_map), so an IP's
    # packets, l7_events and iocs all land in the same bucket number.
    for src_view, out_dir in (("packets", lib.PACKETS_CLUSTERED),
                              ("l7_events", lib.L7_CLUSTERED),
                              ("iocs", lib.IOCS_CLUSTERED)):
        cluster_table(con, src_view, out_dir, n, where)

    con.close()
    try:
        ip_map.unlink()
    except OSError:
        pass
    print("[cluster] done", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--buckets", type=int,
                    default=int(os.environ.get("SG_CLUSTER_BUCKETS",
                                               DEFAULT_BUCKETS)),
                    help="number of hash(asn) buckets (default 128)")
    lib.add_window_args(ap)
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())

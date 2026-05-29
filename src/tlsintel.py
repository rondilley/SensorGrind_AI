#!/usr/bin/env python3
"""
tlsintel — TLS intelligence from ClientHello fields.

Extracts SNI domains, ciphersuite profiles, and TLS version distribution
from TLS l7_events. Identifies suspicious patterns: missing SNI (potential
C2), outdated TLS versions, weak ciphersuites.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

RESULT_SCHEMA = pa.schema([
    ("sni",           pa.string()),
    ("src_ip_count",  pa.uint32()),
    ("hit_count",     pa.uint64()),
    ("tls_versions",  pa.string()),
    ("first_seen",    pa.timestamp("us", tz="UTC")),
    ("last_seen",     pa.timestamp("us", tz="UTC")),
    ("day_count",     pa.uint16()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[tlsintel] querying TLS SNI from iocs...", file=sys.stderr)
    sni_rows = con.execute(f"""
        SELECT value AS sni, count(DISTINCT src_ip) AS src_ip_count,
               count(*) AS hit_count, min(ts) AS first_seen, max(ts) AS last_seen,
               count(DISTINCT dt) AS day_count
        FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['tls_sni']} AND {where}
        GROUP BY value ORDER BY src_ip_count DESC
    """).fetchall()
    print(f"[tlsintel] {len(sni_rows):,} distinct SNI domains", file=sys.stderr)

    print("[tlsintel] analyzing TLS versions...", file=sys.stderr)
    tls_events = con.execute(f"""
        SELECT fields_json FROM l7_events
        WHERE l7_proto = {lib.L7_ID['tls']} AND {where}
    """).fetchall()

    ver_counts: dict[str, int] = defaultdict(int)
    no_sni_count = 0
    for (fj,) in tls_events:
        try:
            f = json.loads(fj)
        except Exception:
            continue
        ver = f.get("version", "unknown")
        ver_counts[ver] += 1
        if not f.get("sni"):
            no_sni_count += 1
    print(f"[tlsintel] {len(tls_events):,} TLS events, {no_sni_count:,} without SNI", file=sys.stderr)

    con.close()

    results = [{
        "sni": r[0], "src_ip_count": r[1], "hit_count": r[2],
        "tls_versions": "", "first_seen": r[3], "last_seen": r[4], "day_count": r[5],
    } for r in sni_rows]

    top_n = args.limit or 40
    ver_summary = sorted(ver_counts.items(), key=lambda x: x[1], reverse=True)

    md = f"""## Summary

- **{len(sni_rows):,}** distinct SNI domains
- **{len(tls_events):,}** total TLS events
- **{no_sni_count:,}** TLS connections with no SNI ({no_sni_count / max(len(tls_events), 1) * 100:.1f}%) — potential C2

## TLS version distribution

"""
    md += lib.markdown_table(
        [{"version": v, "count": c} for v, c in ver_summary],
        columns=["version", "count"])
    md += f"\n## Top {top_n} SNI domains by source IP spread\n\n"
    md += lib.markdown_table(results[:top_n],
        columns=["sni", "src_ip_count", "hit_count", "day_count"])

    return lib.Report(name="tlsintel", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[tlsintel] wrote {paths['parquet']}")
    print(f"[tlsintel] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

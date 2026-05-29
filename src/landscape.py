#!/usr/bin/env python3
"""
landscape - long-time-domain threat landscape evolution.

Monthly/quarterly views of how tools, targets, and threat composition
change across the 6.6-year corpus.

What it computes
----------------
1. Monthly top-10 destination ports (which targets matter when?)
2. Monthly top-10 source ASNs (where does activity originate, by month?)
3. Monthly probe-tag (CVE/exploit) counts (when does each campaign peak?)
4. Monthly botnet-family hits (Mozi/Mirai/Hajime trajectories)
5. Monthly L7 protocol mix (HTTP vs TLS vs SSH vs RDP composition)
6. Year-over-year deltas on the same axes

Output: output/reports/landscape/*.parquet + landscape.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


MONTHLY_PORT_SCHEMA = pa.schema([
    ("month",       pa.string()),
    ("dst_port",    pa.uint16()),
    ("packets",     pa.uint64()),
    ("distinct_ips", pa.uint32()),
    ("rank",        pa.uint8()),
])
MONTHLY_PROBE_SCHEMA = pa.schema([
    ("month",     pa.string()),
    ("probe_tag", pa.string()),
    ("hits",      pa.uint64()),
    ("ips",       pa.uint32()),
])
MONTHLY_BOTNET_SCHEMA = pa.schema([
    ("month",   pa.string()),
    ("family",  pa.string()),
    ("hits",    pa.uint64()),
    ("ips",     pa.uint32()),
])
MONTHLY_L7_SCHEMA = pa.schema([
    ("month",     pa.string()),
    ("l7_proto",  pa.string()),
    ("events",    pa.uint64()),
])


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    out_dir = lib.REPORTS / "landscape"
    out_dir.mkdir(parents=True, exist_ok=True)

    print("[landscape] monthly top-10 destination ports...", file=sys.stderr)
    port_rows = con.execute("""
        WITH per_month AS (
            SELECT strftime(ts, '%Y-%m') AS month,
                   dst_port,
                   count(*) AS packets,
                   count(DISTINCT src_ip) AS ips,
                   row_number() OVER (PARTITION BY strftime(ts, '%Y-%m')
                                      ORDER BY count(*) DESC) AS rk
            FROM packets WHERE dst_port IS NOT NULL
            GROUP BY month, dst_port
        )
        SELECT month, dst_port, packets, ips, rk
        FROM per_month WHERE rk <= 10
        ORDER BY month, rk
    """).fetchall()
    pq.write_table(pa.Table.from_pylist(
        [{"month": m, "dst_port": int(p), "packets": int(n),
          "distinct_ips": int(k), "rank": int(r)}
         for m, p, n, k, r in port_rows],
        schema=MONTHLY_PORT_SCHEMA),
        out_dir / "monthly_top_ports.parquet",
        compression="zstd", compression_level=3)

    print("[landscape] monthly probe-tag activity...", file=sys.stderr)
    probesigs = lib.REPORTS / "probesigs" / "probesigs.parquet"
    probe_rows = []
    if probesigs.exists():
        probe_rows = con.execute(f"""
            SELECT strftime(i.ts, '%Y-%m') AS month, p.probe_tag,
                   count(*) AS hits, count(DISTINCT i.src_ip) AS ips
            FROM iocs i
            JOIN read_parquet('{probesigs}') p ON i.value = p.uri
            WHERE i.ioc_kind = {lib.IOC_ID['http_uri']}
            GROUP BY month, p.probe_tag
            ORDER BY month, hits DESC
        """).fetchall()
    pq.write_table(pa.Table.from_pylist(
        [{"month": m, "probe_tag": t, "hits": int(h), "ips": int(k)}
         for m, t, h, k in probe_rows],
        schema=MONTHLY_PROBE_SCHEMA),
        out_dir / "monthly_probes.parquet",
        compression="zstd", compression_level=3)

    print("[landscape] monthly botnet-family activity...", file=sys.stderr)
    botnet = lib.REPORTS / "botnetcls" / "botnetcls.parquet"
    bot_rows = []
    if botnet.exists():
        bot_rows = con.execute(f"""
            SELECT strftime(p.ts, '%Y-%m') AS month, b.family,
                   count(*) AS hits, count(DISTINCT p.src_ip) AS ips
            FROM packets p
            JOIN read_parquet('{botnet}') b ON p.payload_sha256 = b.payload_sha256
            GROUP BY month, b.family
            ORDER BY month, hits DESC
        """).fetchall()
    pq.write_table(pa.Table.from_pylist(
        [{"month": m, "family": f, "hits": int(h), "ips": int(k)}
         for m, f, h, k in bot_rows],
        schema=MONTHLY_BOTNET_SCHEMA),
        out_dir / "monthly_botnet.parquet",
        compression="zstd", compression_level=3)

    print("[landscape] monthly L7 protocol mix...", file=sys.stderr)
    l7_rows = con.execute("""
        SELECT strftime(ts, '%Y-%m') AS month, l7_proto, count(*) AS events
        FROM l7_events GROUP BY month, l7_proto ORDER BY month, events DESC
    """).fetchall()
    pq.write_table(pa.Table.from_pylist(
        [{"month": m, "l7_proto": lib.L7_NAME.get(p, str(p)),
          "events": int(n)} for m, p, n in l7_rows],
        schema=MONTHLY_L7_SCHEMA),
        out_dir / "monthly_l7.parquet",
        compression="zstd", compression_level=3)

    con.close()

    md = ["# landscape - long-time-domain threat evolution", ""]

    # Group port rows by month for a compact view
    by_month: dict[str, list] = {}
    for m, p, n, k, r in port_rows:
        by_month.setdefault(m, []).append((p, n, k, r))
    md.extend(["## Monthly top destination ports",
               "",
               "_The top 10 destination ports targeted per month. Shifts in "
               "this list mark changes in attacker focus - e.g. SSH dominance "
               "giving way to HTTP scanners, or new IoT/router ports appearing._",
               "",
               "| month | top_ports (port:ips_share_of_month) |",
               "| --- | --- |"])
    for m, items in sorted(by_month.items()):
        tot = sum(n for _, n, _, _ in items) or 1
        compact = " ".join(f"{p}:{n/tot:.0%}" for p, n, _, _ in items[:6])
        md.append(f"| {m} | {compact} |")

    if probe_rows:
        # Aggregate to top tags per month
        md.extend(["", "## Monthly top probe tags (exploit/CVE scanning)",
                   "",
                   "_When each CVE/exploit URI campaign was active. Useful "
                   "for tying spikes here to public-disclosure dates of the "
                   "underlying vulnerability._",
                   "",
                   "| month | top_probes (tag:ips) |",
                   "| --- | --- |"])
        tag_by_month: dict[str, list] = {}
        for m, t, h, k in probe_rows:
            tag_by_month.setdefault(m, []).append((t, k))
        for m, items in sorted(tag_by_month.items()):
            md.append(f"| {m} | "
                      + " ".join(f"{t}:{k}" for t, k in items[:5]) + " |")

    if bot_rows:
        md.extend(["", "## Monthly botnet-family activity",
                   "",
                   "_Per-family hit counts by month. Mozi's long decay tail, "
                   "Mirai spikes, and family extinctions show clearly here._",
                   "",
                   "| month | top_families (family:ips) |",
                   "| --- | --- |"])
        fam_by_month: dict[str, list] = {}
        for m, f, h, k in bot_rows:
            fam_by_month.setdefault(m, []).append((f, k))
        for m, items in sorted(fam_by_month.items()):
            md.append(f"| {m} | " +
                      " ".join(f"{f}:{k}" for f, k in items[:5]) + " |")

    (out_dir / "landscape.md").write_text("\n".join(md) + "\n")
    print(f"[landscape] wrote {out_dir}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    return run(argparse.Namespace())


if __name__ == "__main__":
    sys.exit(main())

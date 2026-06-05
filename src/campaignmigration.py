#!/usr/bin/env python3
"""
campaignmigration - map how campaign fingerprints migrate across infrastructure.

A compositeprint ``core_hash`` is one behaviour (stack+sequence+tempo+app+payload)
that is independent of ASN/CIDR/IP.  When the SAME core_hash shows up on many
networks over time, that is one campaign/operator rotating its hosting to dodge
blocklists and filtering.  This stage turns that into three actionable maps:

  1. Per-campaign migration timeline -- a Gantt of which ASNs each campaign was
     active on, when.  Reads as the hand-off: AS-A goes quiet, AS-B lights up.

  2. ISP-collaboration graph -- ASNs are linked when they host the SAME campaign
     fingerprint (co-hosting), and directed when a campaign moves A -> B between
     days (hand-off).  ASNs tightly linked by shared campaigns over time are the
     complicit / bulletproof / persistently-compromised network cluster.

  3. Compromised-host churn -- per source IP: how many distinct campaigns used
     it and for how long.  Transient single-campaign IPs are throwaway/cycled
     compromised hosts; long-lived multi-campaign IPs are persistent relays.

Inputs: output/reports/compositeprint/{composite,clusters}.parquet.
Daily time windows.  Infrastructure axis only (no geo basemap).
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from itertools import combinations
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib
from report.render import mermaid_gantt, mermaid_sankey, mermaid_flowchart, mm_trunc


MIN_ASNS      = 3     # a campaign must span >= this many ASNs to be "migrating"
MIN_IPS       = 3     # ...and >= this many source IPs
TOP_TIMELINE  = 25    # per-campaign Gantt charts to render (data has all)
TOP_EDGES     = 40    # ISP-graph edges to plot
MAX_ASN_PAIR  = 15    # cap ASNs/campaign used for pairwise co-host edges
PERSIST_DAYS  = 7     # active >= this many days -> "persistent relay"


MIGRATION_SCHEMA = pa.schema([
    ("core_hash",   pa.string()),
    ("day",         pa.string()),
    ("asn",         pa.uint32()),
    ("asn_org",     pa.string()),
    ("ip_count",    pa.uint32()),
    ("cidr_count",  pa.uint32()),
    ("packets",     pa.uint64()),
    ("first_seen",  pa.timestamp("us", tz="UTC")),
    ("last_seen",   pa.timestamp("us", tz="UTC")),
])

ISP_COLLAB_SCHEMA = pa.schema([
    ("kind",              pa.string()),   # 'cohost' | 'handoff'
    ("src_asn",           pa.uint32()),
    ("src_org",           pa.string()),
    ("dst_asn",           pa.uint32()),
    ("dst_org",           pa.string()),
    ("shared_campaigns",  pa.uint32()),
    ("sample_core",       pa.string()),
])

HOST_SCHEMA = pa.schema([
    ("src_ip",       pa.string()),
    ("host_class",   pa.string()),    # 'cycled' | 'persistent' | 'transient'
    ("n_campaigns",  pa.uint32()),
    ("active_days",  pa.uint32()),
    ("packets",      pa.uint64()),
    ("asn",          pa.uint32()),
    ("cidr",         pa.string()),
    ("country_iso",  pa.string()),
    ("first_seen",   pa.timestamp("us", tz="UTC")),
    ("last_seen",    pa.timestamp("us", tz="UTC")),
])


def _asn_org_map(con) -> dict[int, str]:
    """asn -> org from asnintel if present (for readable graph labels)."""
    p = lib.REPORTS / "asnintel" / "asnintel.parquet"
    if not p.exists():
        return {}
    try:
        rows = con.execute(
            f"SELECT asn, any_value(asn_org) FROM read_parquet('{p.as_posix()}') "
            f"WHERE asn IS NOT NULL GROUP BY asn").fetchall()
        return {int(a): (o or "") for a, o in rows}
    except Exception:
        return {}


def _label(asn: int, orgs: dict[int, str]) -> str:
    org = mm_trunc(orgs.get(int(asn), "") or "", 22)
    return f"AS{asn} {org}".strip()


def _empty_outputs(out_dir: Path) -> None:
    for name, schema in (("migration", MIGRATION_SCHEMA),
                         ("isp_collab", ISP_COLLAB_SCHEMA),
                         ("compromised_hosts", HOST_SCHEMA)):
        pq.write_table(pa.Table.from_pylist([], schema=schema),
                       out_dir / f"{name}.parquet",
                       compression="zstd", compression_level=3)
    (out_dir / "migration.md").write_text(
        "# campaignmigration\n\n_No migrating campaigns found "
        "(compositeprint clusters absent or no cross-infrastructure "
        "fingerprints this run)._\n")


def run(args: argparse.Namespace) -> int:
    out_dir = lib.REPORTS / "campaignmigration"
    out_dir.mkdir(parents=True, exist_ok=True)
    comp = lib.REPORTS / "compositeprint" / "composite.parquet"
    clusters = lib.REPORTS / "compositeprint" / "clusters.parquet"
    if not comp.exists() or not clusters.exists():
        print("[campaignmigration] compositeprint outputs missing; nothing to do",
              file=sys.stderr)
        _empty_outputs(out_dir)
        return 0

    mem = args.memory_limit or lib.auto_memory_limit(0.4)
    con = lib.duck(memory_limit=mem)
    _cap = int(os.environ.get("SG_MIGRATION_THREADS", "4"))
    con.execute(f"SET threads={max(2, min(_cap, (os.cpu_count() or 4) // 2))}")
    print(f"[campaignmigration] memory_limit={mem}", file=sys.stderr)

    # 1. Migrating campaigns = cross-infra core_hashes (drop generic ICMP sweeps).
    con.execute(f"""
        CREATE TEMP TABLE camp AS
        SELECT core_hash, n_ips, n_asns, seq_chain, present, dom_proto, tier
        FROM read_parquet('{clusters.as_posix()}')
        WHERE cross_infra = TRUE
          AND n_asns >= {MIN_ASNS} AND n_ips >= {MIN_IPS}
          AND seq_chain NOT LIKE 'ICMP/8.0%'
    """)
    n_camp = con.execute("SELECT count(*) FROM camp").fetchone()[0]
    if n_camp == 0:
        print("[campaignmigration] no migrating campaigns", file=sys.stderr)
        _empty_outputs(out_dir)
        con.close()
        return 0
    print(f"[campaignmigration] {n_camp:,} migrating campaigns", file=sys.stderr)
    orgs = _asn_org_map(con)

    # 2. Migration timeline: per (campaign, day, ASN).  SEMI JOIN bounds the
    #    scan to the selected campaigns' episodes.
    mig = con.execute(f"""
        SELECT c.core_hash,
               CAST(c.first_seen AS DATE)::VARCHAR        AS day,
               c.asn,
               count(DISTINCT c.src_ip)::UINTEGER         AS ip_count,
               count(DISTINCT c.cidr)::UINTEGER           AS cidr_count,
               sum(c.pkt_count)::UBIGINT                  AS packets,
               min(c.first_seen)                          AS first_seen,
               max(c.last_seen)                           AS last_seen
        FROM read_parquet('{comp.as_posix()}') c
        SEMI JOIN camp t ON c.core_hash = t.core_hash
        WHERE c.asn IS NOT NULL
        GROUP BY c.core_hash, day, c.asn
    """).fetchall()
    mig_rows = [{
        "core_hash": r[0], "day": r[1], "asn": int(r[2]),
        "asn_org": orgs.get(int(r[2]), ""), "ip_count": int(r[3]),
        "cidr_count": int(r[4]), "packets": int(r[5] or 0),
        "first_seen": r[6], "last_seen": r[7],
    } for r in mig]
    pq.write_table(pa.Table.from_pylist(mig_rows, schema=MIGRATION_SCHEMA),
                   out_dir / "migration.parquet",
                   compression="zstd", compression_level=3)
    print(f"[campaignmigration] {len(mig_rows):,} (campaign, day, ASN) rows",
          file=sys.stderr)

    # 3. Compromised-host churn: per source IP across migrating campaigns.
    hosts = con.execute(f"""
        SELECT c.src_ip,
               count(DISTINCT c.core_hash)::UINTEGER      AS n_campaigns,
               count(DISTINCT CAST(c.first_seen AS DATE))::UINTEGER AS active_days,
               sum(c.pkt_count)::UBIGINT                  AS packets,
               any_value(c.asn)                           AS asn,
               any_value(c.cidr)                          AS cidr,
               any_value(c.country_iso)                   AS country_iso,
               min(c.first_seen)                          AS first_seen,
               max(c.last_seen)                           AS last_seen
        FROM read_parquet('{comp.as_posix()}') c
        SEMI JOIN camp t ON c.core_hash = t.core_hash
        GROUP BY c.src_ip
    """).fetchall()
    con.close()

    host_rows = []
    cls_counts: dict[str, int] = defaultdict(int)
    for ip, ncamp, adays, pkts, asn, cidr, ciso, fs, ls in hosts:
        ncamp = int(ncamp); adays = int(adays)
        if ncamp >= 2:
            cls = "cycled"            # reused across distinct campaigns
        elif adays >= PERSIST_DAYS:
            cls = "persistent"        # one campaign, long-lived relay
        else:
            cls = "transient"         # short-lived throwaway host
        cls_counts[cls] += 1
        host_rows.append({
            "src_ip": ip, "host_class": cls, "n_campaigns": ncamp,
            "active_days": adays, "packets": int(pkts or 0),
            "asn": int(asn) if asn is not None else 0,
            "cidr": cidr or "", "country_iso": ciso or "",
            "first_seen": fs, "last_seen": ls,
        })
    host_rows.sort(key=lambda h: (h["n_campaigns"], h["active_days"],
                                  h["packets"]), reverse=True)
    pq.write_table(pa.Table.from_pylist(host_rows, schema=HOST_SCHEMA),
                   out_dir / "compromised_hosts.parquet",
                   compression="zstd", compression_level=3)

    # 4. ISP-collaboration graph (computed from the migration rows).
    by_camp: dict[str, dict] = defaultdict(
        lambda: {"asn_ips": defaultdict(int), "day_asns": defaultdict(set)})
    for r in mig_rows:
        ch = r["core_hash"]
        by_camp[ch]["asn_ips"][r["asn"]] += r["ip_count"]
        by_camp[ch]["day_asns"][r["day"]].add(r["asn"])

    cohost: dict[tuple[int, int], dict] = defaultdict(
        lambda: {"n": 0, "core": ""})
    handoff: dict[tuple[int, int], dict] = defaultdict(
        lambda: {"n": 0, "core": ""})
    for ch, d in by_camp.items():
        # co-host: ASN pairs that both serve this campaign (top ASNs by IPs,
        # capped so a diffuse botnet doesn't explode into N^2 edges).
        top_asns = sorted(d["asn_ips"], key=lambda a: -d["asn_ips"][a])[:MAX_ASN_PAIR]
        for a, b in combinations(sorted(top_asns), 2):
            e = cohost[(a, b)]; e["n"] += 1; e["core"] = e["core"] or ch
        # hand-off: between consecutive active days, ASNs that vanish -> ASNs
        # that newly appear (the campaign moved hosting).
        days = sorted(d["day_asns"])
        for d0, d1 in zip(days, days[1:]):
            gone = d["day_asns"][d0] - d["day_asns"][d1]
            new  = d["day_asns"][d1] - d["day_asns"][d0]
            for a in gone:
                for b in new:
                    e = handoff[(a, b)]; e["n"] += 1; e["core"] = e["core"] or ch

    collab_rows = []
    for (a, b), e in cohost.items():
        if e["n"] >= 2:   # shared by >=2 campaigns = real collaboration signal
            collab_rows.append({
                "kind": "cohost", "src_asn": a, "src_org": orgs.get(a, ""),
                "dst_asn": b, "dst_org": orgs.get(b, ""),
                "shared_campaigns": e["n"], "sample_core": e["core"]})
    for (a, b), e in handoff.items():
        if e["n"] >= 2:
            collab_rows.append({
                "kind": "handoff", "src_asn": a, "src_org": orgs.get(a, ""),
                "dst_asn": b, "dst_org": orgs.get(b, ""),
                "shared_campaigns": e["n"], "sample_core": e["core"]})
    collab_rows.sort(key=lambda x: x["shared_campaigns"], reverse=True)
    pq.write_table(pa.Table.from_pylist(collab_rows, schema=ISP_COLLAB_SCHEMA),
                   out_dir / "isp_collab.parquet",
                   compression="zstd", compression_level=3)
    print(f"[campaignmigration] {len(collab_rows):,} ISP-collab edges "
          f"(cohost+handoff, >=2 campaigns)", file=sys.stderr)

    _write_markdown(out_dir, mig_rows, collab_rows, host_rows, cls_counts,
                    n_camp, orgs)
    print(f"[campaignmigration] wrote {out_dir}", file=sys.stderr)
    return 0


def _write_markdown(out_dir, mig_rows, collab_rows, host_rows, cls_counts,
                    n_camp, orgs) -> None:
    # Per-campaign rollup for picking the most-spread campaigns to plot.
    camp_asns: dict[str, set] = defaultdict(set)
    camp_ips: dict[str, int] = defaultdict(int)
    camp_seq: dict[str, str] = {}
    rows_by_camp: dict[str, list] = defaultdict(list)
    for r in mig_rows:
        camp_asns[r["core_hash"]].add(r["asn"])
        camp_ips[r["core_hash"]] += r["ip_count"]
        rows_by_camp[r["core_hash"]].append(r)
    top_camps = sorted(camp_asns, key=lambda c: (len(camp_asns[c]), camp_ips[c]),
                       reverse=True)[:TOP_TIMELINE]

    md = ["# campaignmigration - fingerprint migration across infrastructure", "",
          "_Each campaign is one compositeprint `core_hash` (a behaviour "
          "independent of ASN/CIDR/IP).  The same fingerprint appearing on many "
          "networks over time is one operator rotating hosting to evade "
          "blocklists.  Daily windows._", "",
          f"- **{n_camp:,}** migrating campaigns (cross-infra, >= {MIN_ASNS} "
          f"ASNs / {MIN_IPS} IPs)",
          f"- **{cls_counts.get('cycled', 0):,}** cycled hosts (reused across "
          f">= 2 campaigns), **{cls_counts.get('persistent', 0):,}** persistent "
          f"relays (>= {PERSIST_DAYS} active days), "
          f"**{cls_counts.get('transient', 0):,}** transient hosts", ""]

    # ---- View 2: ISP-collaboration graph ----
    md += ["## ISP collaboration / bulletproof network cluster", "",
           "_ASNs linked by hosting the **same** campaign fingerprints.  "
           "`cohost` = both served a campaign; `handoff` = a campaign moved "
           "from one to the other between days.  Edges shared by >= 2 campaigns._",
           ""]
    cohost_edges = [e for e in collab_rows if e["kind"] == "cohost"][:TOP_EDGES]
    handoff_edges = [e for e in collab_rows if e["kind"] == "handoff"][:TOP_EDGES]
    if cohost_edges:
        nodes_seen = {}
        fedges = []
        for e in cohost_edges:
            for a in (e["src_asn"], e["dst_asn"]):
                nodes_seen[f"AS{a}"] = _label(a, orgs)
            fedges.append((f"AS{e['src_asn']}", f"AS{e['dst_asn']}",
                           str(e["shared_campaigns"])))
        md += ["### Co-hosting graph (ASNs serving the same campaigns)", "",
               mermaid_flowchart("LR", list(nodes_seen.items()), fedges), ""]
    if handoff_edges:
        md += ["### Migration hand-offs (campaign moved AS-A -> AS-B)", "",
               mermaid_sankey([(_label(e["src_asn"], orgs),
                                _label(e["dst_asn"], orgs),
                                e["shared_campaigns"]) for e in handoff_edges]), ""]
    if not cohost_edges and not handoff_edges:
        md += ["_No ASN pairs shared by >= 2 campaigns this run._", ""]

    # ---- View 1: per-campaign migration timelines ----
    md += ["## Per-campaign migration timelines", "",
           f"_Top {len(top_camps)} most-distributed campaigns.  Each row is an "
           "ASN; the bar spans the days the campaign was active there.  Reading "
           "left-to-right shows the hand-off as it migrates._", ""]
    for ch in top_camps:
        rows = rows_by_camp[ch]
        # one Gantt task per ASN: [first active day, last active day + 1)
        per_asn: dict[int, list] = defaultdict(list)
        for r in rows:
            per_asn[r["asn"]].append(r["day"])
        items = []
        for asn in sorted(per_asn, key=lambda a: min(per_asn[a])):
            days = sorted(per_asn[asn])
            start = days[0]
            end = _next_day(days[-1])
            ips = sum(r["ip_count"] for r in rows if r["asn"] == asn)
            items.append((_label(asn, orgs), f"{ips}ip", start, end))
        seq = (camp_seq.get(ch) or "")
        title = f"{ch[:10]} - {len(per_asn)} ASNs / {camp_ips[ch]} IPs"
        md += [f"### `{ch[:12]}` ({len(per_asn)} ASNs, {camp_ips[ch]} IPs)", "",
               mermaid_gantt(title, items), ""]

    # ---- View 3: compromised-host churn ----
    md += ["## Compromised-host churn (top cycled / persistent hosts)", "",
           "_Hosts reused across multiple campaigns or active many days -- "
           "candidate compromised relays being cycled to dodge filtering._", "",
           "| src_ip | class | campaigns | active_days | packets | asn | country |",
           "| --- | --- | --- | --- | --- | --- | --- |"]
    for h in host_rows[:40]:
        md.append(f"| {h['src_ip']} | {h['host_class']} | {h['n_campaigns']} "
                  f"| {h['active_days']} | {h['packets']:,} | AS{h['asn']} "
                  f"| {h['country_iso']} |")
    (out_dir / "migration.md").write_text("\n".join(md) + "\n")


def _next_day(day: str) -> str:
    import datetime as _dt
    try:
        return (_dt.date.fromisoformat(day) + _dt.timedelta(days=1)).isoformat()
    except ValueError:
        return day


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    ap.add_argument("--memory-limit", default=None,
                    help="DuckDB memory cap (default: auto, ~40%% of host RAM).")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

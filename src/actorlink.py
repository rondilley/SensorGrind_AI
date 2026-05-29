#!/usr/bin/env python3
"""
actorlink - multi-signal cooperative-actor detection via graph community
detection.

Goal: defender-facing answer to "which IPs are working together as the
same operator/group, even though they're spread across different IPs,
ASNs and countries?"

Construction
------------
Build an undirected weighted graph where each node is a source IP that
qualifies as a threat (>= medium tier).  Edges are added when two IPs
share any of:

  - the same payload SHA-256                          weight 4.0
  - the same user-agent hash (from iocs)              weight 2.0
  - the same JA4T fingerprint (TCP SYN-only)          weight 2.0
  - the same probesigs probe_tag                      weight 1.0
  - the same RDP mstshash cookie                      weight 3.0
  - very similar pacing (median IAT within 10%)       weight 1.5
  - first-seen within 60s (synchronized arrival)      weight 1.0

Edge weights are summed across signals.  We then run Louvain community
detection (python-louvain) and report communities with >= MIN_MEMBERS
members.  For each community we emit:

  - member IPs (sample)
  - dominant ASN(s) and countries
  - shared evidence (which signals connected the members)
  - aggregate risk_score
  - implied tooling fingerprint (most common JA4T / UA)
  - implied targeting (most common dst_ports / probe_tags)
  - first/last activity span

This is the "actor atlas" - each community is one candidate actor,
with concrete attribution evidence.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
OUT_DIR = lib.REPORTS / "actorlink"

NODE_SCHEMA = pa.schema([
    ("community_id",  pa.uint32()),
    ("src_ip",        pa.string()),
    ("risk_score",    pa.float32()),
    ("asn",           pa.uint32()),
    ("asn_org",       pa.string()),
    ("country_iso",   pa.string()),
])

COMMUNITY_SCHEMA = pa.schema([
    ("community_id",  pa.uint32()),
    ("member_count",  pa.uint32()),
    ("avg_risk",      pa.float32()),
    ("countries",     pa.string()),
    ("top_asns",      pa.string()),
    ("shared_signals", pa.string()),
    ("dominant_tools", pa.string()),
    ("dominant_targets", pa.string()),
    ("first_seen",    pa.timestamp("us", tz="UTC")),
    ("last_seen",     pa.timestamp("us", tz="UTC")),
    ("sample_ips",    pa.string()),
])


SIGNAL_WEIGHTS = {
    "payload_sha":  4.0,
    "ua_hash":      2.0,
    "ja4t":         2.0,
    "probe_tag":    1.0,
    "mstshash":     3.0,
    "pacing_close": 1.5,
    "first_seen_close": 1.0,
}


def run(args: argparse.Namespace) -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[actorlink] no ip features", file=sys.stderr)
        return 2
    feat_path = sf.snapshot_dir(snap) / "part-0000.parquet"
    risk_path = (lib.OUTPUT_DIR / "risk" / "ip_risk"
                 / f"dt={snap.snapshot_date.isoformat()}" / "risk.parquet")
    if not risk_path.exists():
        print("[actorlink] no risk file", file=sys.stderr)
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    # ---- pick threat IPs ----
    print("[actorlink] selecting threat IPs (tier >= medium)...",
          file=sys.stderr)
    ips_meta = con.execute(f"""
        SELECT r.src_ip, r.risk_score, f.asn, f.asn_org, f.country_iso
        FROM read_parquet('{risk_path}') r
        JOIN read_parquet('{feat_path}') f ON r.src_ip = f.src_ip
        WHERE r.risk_tier IN ('critical', 'high', 'medium')
        ORDER BY r.risk_score DESC
        LIMIT {args.top_ips}
    """).fetchall()
    if not ips_meta:
        print("[actorlink] no threat IPs found", file=sys.stderr)
        return 0
    ip_meta = {r[0]: r for r in ips_meta}
    ip_set = set(ip_meta)
    ip_list_csv = "(" + ",".join(f"'{ip}'" for ip in ip_set) + ")"
    print(f"[actorlink] {len(ip_set):,} threat IPs in graph", file=sys.stderr)

    # ---- gather per-signal IP groupings ----
    # Stage gathered groups into a temp table of in-set IPs to limit the
    # range query scope, and pre-filter group size at the SQL level so we
    # never materialize an oversized `list(...)` aggregate.
    con.execute("CREATE TEMP TABLE al_ips(ip VARCHAR)")
    con.executemany("INSERT INTO al_ips VALUES (?)", [(ip,) for ip in ip_set])

    payload_groups: list = []
    if not args.skip_payload:
        # Use the existing `campaign` parquet (payload_sha -> IP list) when
        # available - it's the same clustering already done, just narrowed
        # to our threat IPs.  Avoids a fresh full-scan of `packets`.
        camp_path = lib.REPORTS / "campaign" / "campaign.parquet"
        if camp_path.exists():
            print("[actorlink] reading shared-payload signal from campaign output...",
                  file=sys.stderr)
            rows = con.execute(f"""
                SELECT sample_ips
                FROM read_parquet('{camp_path}')
                WHERE ip_count BETWEEN 2 AND {args.max_group_size}
            """).fetchall()
            for (samples_str,) in rows:
                if not samples_str:
                    continue
                grp = [x.strip() for x in samples_str.split(",") if x.strip() in ip_set]
                if 2 <= len(grp) <= args.max_group_size:
                    payload_groups.append(grp)
            print(f"[actorlink]   payload groups (from campaign): "
                  f"{len(payload_groups):,}", file=sys.stderr)
        else:
            print("[actorlink]   no campaign output - skipping payload signal",
                  file=sys.stderr)

    print("[actorlink] gathering shared-UA signal...", file=sys.stderr)
    rows = con.execute(f"""
        WITH counted AS (
            SELECT value, count(DISTINCT src_ip) AS n
            FROM iocs i SEMI JOIN al_ips t ON i.src_ip = t.ip
            WHERE ioc_kind = {lib.IOC_ID['user_agent']}
            GROUP BY value
            HAVING count(DISTINCT src_ip) BETWEEN 2 AND {args.max_group_size}
        )
        SELECT i.value, list(DISTINCT i.src_ip)
        FROM iocs i SEMI JOIN al_ips t ON i.src_ip = t.ip
        JOIN counted c USING (value)
        WHERE i.ioc_kind = {lib.IOC_ID['user_agent']}
        GROUP BY i.value
    """).fetchall()
    ua_groups = [list(r[1]) for r in rows]
    print(f"[actorlink]   UA groups: {len(ua_groups):,}", file=sys.stderr)

    print("[actorlink] gathering shared-mstshash signal...", file=sys.stderr)
    rows = con.execute(f"""
        SELECT value, list(DISTINCT i.src_ip)
        FROM iocs i SEMI JOIN al_ips t ON i.src_ip = t.ip
        WHERE i.ioc_kind = {lib.IOC_ID['mstshash']}
        GROUP BY value
        HAVING count(DISTINCT i.src_ip) BETWEEN 2 AND {args.max_group_size}
    """).fetchall()
    msts_groups = [list(r[1]) for r in rows]
    print(f"[actorlink]   mstshash groups: {len(msts_groups):,}",
          file=sys.stderr)

    print("[actorlink] gathering shared probe-tag signal...", file=sys.stderr)
    probes_path = lib.REPORTS / "probesigs" / "probesigs.parquet"
    probe_groups = []
    if probes_path.exists():
        rows = con.execute(f"""
            SELECT p.probe_tag, list(DISTINCT i.src_ip)
            FROM iocs i
            SEMI JOIN al_ips t ON i.src_ip = t.ip
            JOIN read_parquet('{probes_path}') p ON i.value = p.uri
            WHERE i.ioc_kind = {lib.IOC_ID['http_uri']}
            GROUP BY p.probe_tag
            HAVING count(DISTINCT i.src_ip) BETWEEN 2 AND {args.max_group_size}
        """).fetchall()
        probe_groups = [list(r[1]) for r in rows]
    print(f"[actorlink]   probe-tag groups: {len(probe_groups):,}",
          file=sys.stderr)

    print("[actorlink] gathering JA4T fingerprint signal...", file=sys.stderr)
    ja4t_groups = []
    ja_path = lib.REPORTS / "ja4plus" / "ja4plus.parquet"
    if ja_path.exists():
        rows = con.execute(f"""
            SELECT fingerprint, list(DISTINCT j.src_ip)
            FROM read_parquet('{ja_path}') j
            SEMI JOIN al_ips t ON j.src_ip = t.ip
            WHERE j.fp_type = 'ja4t'
            GROUP BY fingerprint
            HAVING count(DISTINCT j.src_ip) BETWEEN 2 AND {args.max_group_size}
        """).fetchall()
        ja4t_groups = [list(r[1]) for r in rows]
    print(f"[actorlink]   JA4T groups: {len(ja4t_groups):,}", file=sys.stderr)

    # ---- synchronized arrival ----
    arrival_groups: list = []
    if not args.skip_arrival:
        print("[actorlink] looking for synchronized arrivals (per minute)...",
              file=sys.stderr)
        rows = con.execute(f"""
            WITH fs AS (
                SELECT p.src_ip, min(p.ts) AS first_ts
                FROM packets p SEMI JOIN al_ips t ON p.src_ip = t.ip
                GROUP BY p.src_ip
            ),
            sized AS (
                SELECT date_trunc('minute', first_ts) AS bucket,
                       count(*) AS n
                FROM fs GROUP BY bucket
                HAVING count(*) BETWEEN 2 AND {args.max_group_size}
            )
            SELECT s.bucket, list(f.src_ip)
            FROM fs f
            JOIN sized s ON date_trunc('minute', f.first_ts) = s.bucket
            GROUP BY s.bucket
        """).fetchall()
        arrival_groups = [list(r[1]) for r in rows]
        print(f"[actorlink]   synchronized-arrival groups: "
              f"{len(arrival_groups):,}", file=sys.stderr)

    con.close()

    # ---- build graph ----
    # Accumulate edges in a plain dict first - much cheaper than
    # networkx during the combinatorial expansion step.
    print("[actorlink] accumulating edge weights from each signal...",
          file=sys.stderr)
    edges: dict[tuple[str, str], dict] = {}

    def _add_edges(groups: list[list[str]], signal: str) -> int:
        w = SIGNAL_WEIGHTS[signal]
        added = 0
        skipped_oversize = 0
        for grp in groups:
            grp = [x for x in grp if x in ip_set]
            if len(grp) < 2:
                continue
            if len(grp) > args.max_group_size:
                skipped_oversize += 1
                continue
            for a, b in combinations(sorted(grp), 2):
                key = (a, b)
                e = edges.get(key)
                if e is None:
                    edges[key] = {"weight": w, "signals": {signal}}
                else:
                    e["weight"] += w
                    e["signals"].add(signal)
                added += 1
        if skipped_oversize:
            print(f"[actorlink]   skipped {skipped_oversize} oversize "
                  f"{signal} groups (> {args.max_group_size})", file=sys.stderr)
        return added

    n_p = _add_edges(payload_groups, "payload_sha")
    n_u = _add_edges(ua_groups, "ua_hash")
    n_m = _add_edges(msts_groups, "mstshash")
    n_pr = _add_edges(probe_groups, "probe_tag")
    n_j = _add_edges(ja4t_groups, "ja4t")
    n_a = _add_edges(arrival_groups, "first_seen_close")
    print(f"[actorlink]   ops: payload={n_p:,}, ua={n_u:,}, "
          f"msts={n_m:,}, probe={n_pr:,}, ja4t={n_j:,}, "
          f"arrival={n_a:,}; distinct edges={len(edges):,}",
          file=sys.stderr)

    if not edges:
        print("[actorlink] no edges found; nothing to cluster",
              file=sys.stderr)
        return 0

    print("[actorlink] building networkx graph from edge dict...",
          file=sys.stderr)
    import networkx as nx
    G = nx.Graph()
    for ip, meta in ip_meta.items():
        G.add_node(ip, risk=float(meta[1] or 0))
    for (a, b), data in edges.items():
        G.add_edge(a, b, weight=data["weight"], signals=data["signals"])
    edges.clear()
    print(f"[actorlink]   |V|={G.number_of_nodes():,} |E|={G.number_of_edges():,}",
          file=sys.stderr)

    # ---- Leiden community detection ----
    # Leiden (Traag, 2019, "From Louvain to Leiden: guaranteeing
    # well-connected communities") fixes a known Louvain failure mode
    # where intermediate communities can become internally disconnected.
    # It produces more stable communities at the cost of a slightly
    # heavier algorithm; the multi-AI methodology review converged on
    # this recommendation.  We fall back to Louvain if leidenalg/igraph
    # are unavailable (e.g. on a host where install failed).
    print("[actorlink] running Leiden community detection...",
          file=sys.stderr)
    try:
        import igraph as ig
        import leidenalg
        ip_to_idx = {ip: i for i, ip in enumerate(G.nodes())}
        idx_to_ip = list(G.nodes())
        ig_edges = [(ip_to_idx[u], ip_to_idx[v]) for u, v in G.edges()]
        weights = [G[u][v]["weight"] for u, v in G.edges()]
        gi = ig.Graph(n=len(ip_to_idx), edges=ig_edges, directed=False)
        gi.es["weight"] = weights
        part = leidenalg.find_partition(
            gi, leidenalg.RBConfigurationVertexPartition,
            weights="weight", resolution_parameter=args.resolution, seed=42,
        )
        partition = {idx_to_ip[v]: c for c, members in enumerate(part)
                     for v in members}
        algo_used = "leiden"
    except Exception as e:
        print(f"[actorlink] Leiden unavailable ({e}); "
              "falling back to Louvain", file=sys.stderr)
        import community as community_louvain
        partition = community_louvain.best_partition(G, weight="weight",
                                                     random_state=42)
        algo_used = "louvain"
    print(f"[actorlink] community algorithm used: {algo_used}",
          file=sys.stderr)
    communities: dict[int, list[str]] = defaultdict(list)
    for ip, cid in partition.items():
        communities[cid].append(ip)

    print(f"[actorlink] discovered {len(communities):,} communities; "
          f"emitting those with >= {args.min_members} members",
          file=sys.stderr)

    # ---- compute community summaries ----
    print("[actorlink] enriching communities with metadata...",
          file=sys.stderr)
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    node_rows: list[dict] = []
    com_rows: list[dict] = []
    cid_renum = {}
    next_id = 0
    for cid_orig, members in sorted(communities.items(),
                                    key=lambda kv: -len(kv[1])):
        if len(members) < args.min_members:
            continue
        cid_renum[cid_orig] = next_id
        cid_out = next_id
        next_id += 1

        risks = [G.nodes[ip].get("risk", 0.0) for ip in members]
        countries = Counter(ip_meta[ip][4] for ip in members if ip_meta[ip][4])
        asns = Counter((ip_meta[ip][2], ip_meta[ip][3]) for ip in members
                       if ip_meta[ip][2])
        # which signals actually fired between members of this community?
        signals = Counter()
        sub = G.subgraph(members)
        for _, _, data in sub.edges(data=True):
            for s in data.get("signals", ()):
                signals[s] += 1

        # dominant tools (top ja4t fingerprint among members)
        member_csv = "(" + ",".join(f"'{ip}'" for ip in members[:1000]) + ")"
        tool_rows = []
        if ja_path.exists():
            tool_rows = con.execute(f"""
                SELECT fp_type || '=' || fingerprint AS tool, count(*) AS n
                FROM read_parquet('{ja_path}')
                WHERE src_ip IN {member_csv}
                GROUP BY tool ORDER BY n DESC LIMIT 3
            """).fetchall()
        tools = ", ".join(f"{t}({n})" for t, n in tool_rows)

        # dominant targets (top ports + probe tags)
        port_rows = con.execute(f"""
            SELECT dst_port, count(*) AS n FROM packets
            WHERE src_ip IN {member_csv} AND dst_port IS NOT NULL
            GROUP BY dst_port ORDER BY n DESC LIMIT 5
        """).fetchall()
        ports = ", ".join(f"{p}({n})" for p, n in port_rows)
        targets = ports

        first_last = con.execute(f"""
            SELECT min(ts), max(ts) FROM packets
            WHERE src_ip IN {member_csv}
        """).fetchone()

        com_rows.append({
            "community_id":   cid_out,
            "member_count":   len(members),
            "avg_risk":       float(sum(risks) / len(risks)),
            "countries":      ", ".join(f"{c}({n})" for c, n in countries.most_common(4)),
            "top_asns":       ", ".join(f"AS{a}={(o or '')[:20]}({n})"
                                        for (a, o), n in asns.most_common(4)),
            "shared_signals": ", ".join(f"{s}={n}" for s, n in signals.most_common()),
            "dominant_tools": tools,
            "dominant_targets": targets,
            "first_seen":     first_last[0] if first_last else None,
            "last_seen":      first_last[1] if first_last else None,
            "sample_ips":     ", ".join(sorted(members)[:10]),
        })
        for ip in members:
            meta = ip_meta[ip]
            node_rows.append({
                "community_id": cid_out, "src_ip": ip,
                "risk_score": float(meta[1] or 0),
                "asn": int(meta[2] or 0),
                "asn_org": meta[3] or "",
                "country_iso": meta[4] or "",
            })

    con.close()

    pq.write_table(pa.Table.from_pylist(node_rows, schema=NODE_SCHEMA),
                   OUT_DIR / "nodes.parquet",
                   compression="zstd", compression_level=3)
    pq.write_table(pa.Table.from_pylist(com_rows, schema=COMMUNITY_SCHEMA),
                   OUT_DIR / "communities.parquet",
                   compression="zstd", compression_level=3)

    md = [
        "# actorlink - cooperative-actor detection via multi-signal graph",
        "",
        f"_Built a weighted IP-IP graph over the top "
        f"{len(ip_meta):,} threat IPs.  Edges are added for shared "
        f"payload SHA-256, shared user-agent, shared JA4T fingerprint, "
        f"shared probe-tag, shared mstshash, and synchronized arrival.  "
        f"Louvain community detection produced "
        f"{len(communities):,} groups; **{len(com_rows):,}** have "
        f">= {args.min_members} members and are reported here._",
        "",
        "## Top actor communities by size",
        "",
        "| cid | members | avg_risk | countries | top_asns | shared signals | tools | targets | sample_ips |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in com_rows[:30]:
        md.append(
            f"| {r['community_id']} | {r['member_count']:,} | "
            f"{r['avg_risk']:.1f} | {r['countries']} | {r['top_asns']} | "
            f"{r['shared_signals']} | {r['dominant_tools']} | "
            f"{r['dominant_targets']} | {r['sample_ips']} |"
        )
    (OUT_DIR / "actorlink.md").write_text("\n".join(md) + "\n")
    print(f"[actorlink] wrote {OUT_DIR} ({len(com_rows)} communities)",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--top-ips", type=int, default=10_000,
                    help="Cap input to top-N threat IPs by risk_score")
    ap.add_argument("--min-members", type=int, default=4)
    ap.add_argument("--max-group-size", type=int, default=400,
                    help="Skip 'shared signal' groups bigger than this "
                         "(they're too generic to inform actor attribution "
                         "and cost C(N,2) edges)")
    ap.add_argument("--skip-arrival", action="store_true",
                    help="Skip synchronized-arrival signal (the slowest "
                         "and most prone to oversized buckets)")
    ap.add_argument("--skip-payload", action="store_true",
                    help="Skip payload-sha signal (otherwise reads from "
                         "the existing campaign output if available)")
    ap.add_argument("--resolution", type=float, default=1.0,
                    help="Leiden resolution parameter (>1 = more, smaller "
                         "communities; <1 = fewer, larger).  Default 1.0.")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

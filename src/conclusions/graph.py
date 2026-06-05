#!/usr/bin/env python3
"""
conclusions/graph - KG-lite: fuse cross-signal findings into threat storylines.

correlate.py emits one finding per matched pattern (~dozens per run), and
synthesize.py narrates each ONE IN ISOLATION.  But many findings are facets of
the same operator: they share source IPs, ASNs, an infra-independent fingerprint
(compositeprint core_hash), or a packet-choreography chain.  This stage builds a
small graph linking findings by shared entities and fuses connected findings
into "storylines" so a defender reads ~15 campaigns instead of ~74 disconnected
cards.

Pipeline (dependency-light: networkx + optional python-louvain, both already
deps used by actorlink.py / correlate._asn_communities — same fallback ladder):

    findings.parquet
      -> extract entities per finding (IPs, ASNs, core_hash, chain)
      -> weighted finding<->finding graph (edge = shared-entity weight)
         (an edge needs combined weight >= MIN_EDGE_WEIGHT, so a single shared
          hub ASN can't transitively fuse the whole graph into one blob)
      -> Louvain communities (fallback: connected components) = storylines
      -> aggregate members; record what entity bound each storyline together

Outputs (read by synthesize.py + comprehensive_report + bench/compute_metrics):
  output/conclusions/storylines/storylines.parquet   (one row per storyline)
  output/conclusions/storylines/finding_links.parquet(finding-pair edge list)
  output/conclusions/storylines/storylines.md
  output/conclusions/storylines/summary.json         (consolidation metrics)

IP linking uses correlate's finding_members.parquet — the FULL per-finding source
IP set, not the 25-IP display sample carried in findings.parquet — so two large
findings that overlap outside their samples still fuse.  (The two campaign rules
fed by upstream-sampled summary tables, recent_tight_campaign and the waves-based
ones, are as complete as those summaries expose; everything else is exhaustive.)
A pair's IP-overlap weight is capped (WEIGHT_COUNT_CAP) so one many-IP edge can't
swamp the Louvain partition.  ASN (<=10) stays sample-based and is a weak edge by
design.  core_hash / chain are full-fidelity and are the strongest edges.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib


OUT_DIR = lib.OUTPUT_DIR / "conclusions" / "storylines"

# Edge weights by the SPECIFICITY of the shared entity — mirrors the signal
# weighting in actorlink.py (composite_core=5, payload_sha=4, ...).  core_hash is
# infra-independent so it is the strongest bond; a shared ASN is weak alone
# because a single cloud/hosting ASN is a hub touched by unrelated campaigns.
ENTITY_WEIGHTS = {
    "core_hash": 5.0,   # compositeprint fused fingerprint (fp_rotation findings)
    "chain":     4.0,   # packet-choreography signature (chainfp anomaly findings)
    "ip":        3.0,   # same source host
    "asn":       1.5,   # same network — weak; needs corroboration to count
}

# A finding pair is only linked if its summed shared-entity weight reaches this.
# 3.0 = one shared IP, or one core_hash/chain, or >=2 shared ASNs.  A single
# shared ASN (1.5) is below the bar, so a hub ASN cannot fuse the graph.
MIN_EDGE_WEIGHT = 3.0

# Cap how many shared entities of one type count toward an edge weight.  Two
# findings sharing 5,000 IPs are already maximally linked; without a cap that
# one edge's raw weight would swamp the Louvain partition.  (Thresholding and
# the displayed shared sample are unaffected.)
WEIGHT_COUNT_CAP = 50

# Strong identity keys lifted out of a finding's key_metrics JSON.  IPs/ASNs come
# from the dedicated schema columns; these are the extra full-fidelity bonds.
KEY_METRIC_IDS = ("core_hash", "chain")

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 9}


STORYLINE_SCHEMA = pa.schema([
    ("storyline_id",     pa.string()),
    ("finding_count",    pa.uint32()),
    ("finding_ids",      pa.string()),   # JSON list
    ("pattern_ids",      pa.string()),   # comma-separated, unique
    ("severity",         pa.string()),   # max severity across members
    ("categories",       pa.string()),   # comma-separated, unique
    ("src_ip_count",     pa.uint32()),   # union of member IP samples (see note)
    ("src_ips_sample",   pa.string()),
    ("asns_sample",      pa.string()),
    ("countries_sample", pa.string()),
    ("linking_entities", pa.string()),   # JSON {entity_type: edge_count} that bound it
    ("link_weight_total", pa.float32()),
    ("first_seen",       pa.string()),
    ("last_seen",        pa.string()),
    ("detected_at",      pa.timestamp("us", tz="UTC")),
])

LINK_SCHEMA = pa.schema([
    ("finding_a", pa.string()),
    ("finding_b", pa.string()),
    ("weight",    pa.float32()),
    ("shared",    pa.string()),          # JSON {entity_type: [sample values]}
])


# ----------------------------------------------------------------------
# Pure helpers (unit-tested without a corpus)
# ----------------------------------------------------------------------
def _split(s: str | None, sep: str) -> list[str]:
    return [x.strip() for x in (s or "").split(sep) if x.strip()]


def extract_entities(finding: dict) -> dict[str, set[str]]:
    """Pull the linkable entities out of one finding.

    Returns {entity_type: {values}} for the types in ENTITY_WEIGHTS.  IPs come
    from src_ips_sample, ASNs from asns_sample, and the strong fingerprint keys
    (core_hash, chain) from key_metrics JSON.  Countries are deliberately NOT a
    link type — geography is far too broad to imply a shared operator.
    """
    # IPs come from the FULL finding_members set when run() has attached it
    # (_full_ips); otherwise fall back to the bounded display sample (the path
    # taken by pure unit tests that pass a bare finding dict).
    full_ips = finding.get("_full_ips")
    ips = set(full_ips) if full_ips is not None else set(_split(finding.get("src_ips_sample"), ","))
    ents: dict[str, set[str]] = {
        "ip":  ips,
        "asn": set(_split(finding.get("asns_sample"), ";")),
        "core_hash": set(),
        "chain": set(),
    }
    raw = finding.get("key_metrics")
    if raw:
        try:
            km = json.loads(raw)
        except (ValueError, TypeError):
            km = {}
        for key in KEY_METRIC_IDS:
            v = km.get(key)
            if isinstance(v, str) and v.strip():
                ents[key].add(v.strip())
            elif isinstance(v, (list, tuple)):
                ents[key].update(str(x).strip() for x in v if str(x).strip())
    return ents


def _shared(a: dict[str, set[str]], b: dict[str, set[str]]) -> dict[str, list[str]]:
    """Entities the two findings have in common, by type (non-empty types only)."""
    out: dict[str, list[str]] = {}
    for etype in ENTITY_WEIGHTS:
        common = a.get(etype, set()) & b.get(etype, set())
        if common:
            out[etype] = sorted(common)
    return out


def _edge_weight(shared: dict[str, list[str]]) -> float:
    return sum(ENTITY_WEIGHTS[etype] * min(len(vals), WEIGHT_COUNT_CAP)
               for etype, vals in shared.items())


def build_links(findings: list[dict]) -> list[dict]:
    """Every finding pair whose shared-entity weight clears MIN_EDGE_WEIGHT.

    Each link row carries the pair, the summed weight, and a capped sample of the
    shared entity values (for the report + transparency).
    """
    ents = [extract_entities(f) for f in findings]
    links: list[dict] = []
    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            shared = _shared(ents[i], ents[j])
            if not shared:
                continue
            w = _edge_weight(shared)
            if w < MIN_EDGE_WEIGHT:
                continue
            links.append({
                "finding_a": findings[i]["finding_id"],
                "finding_b": findings[j]["finding_id"],
                "weight":    round(w, 2),
                "shared":    json.dumps({k: v[:10] for k, v in shared.items()},
                                        separators=(",", ":")),
            })
    return links


def fuse(finding_ids: list[str], links: list[dict]) -> list[list[str]]:
    """Partition findings into storylines over the thresholded link graph.

    Louvain (python-louvain, weighted, fixed seed -> deterministic) groups
    tightly-linked findings while letting a single weak bridge split, so one
    promiscuous shared entity does not fuse everything.  Falls back to
    connected-components (union-find) when the graph libs are absent.  Findings
    with no qualifying link are their own singleton storyline.
    """
    try:
        import networkx as nx
        import community as community_louvain
        g = nx.Graph()
        g.add_nodes_from(finding_ids)
        for ln in links:
            g.add_edge(ln["finding_a"], ln["finding_b"], weight=ln["weight"])
        part = community_louvain.best_partition(g, weight="weight", random_state=42)
        groups: dict[int, list[str]] = {}
        for node, cid in part.items():
            groups.setdefault(cid, []).append(node)
        return [sorted(v) for v in groups.values()]
    except Exception:
        return _fuse_union_find(finding_ids, links)


def _fuse_union_find(finding_ids: list[str], links: list[dict]) -> list[list[str]]:
    parent = {fid: fid for fid in finding_ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for ln in links:
        a, b = ln["finding_a"], ln["finding_b"]
        if a in parent and b in parent:
            parent[find(a)] = find(b)
    groups: dict[str, list[str]] = {}
    for fid in finding_ids:
        groups.setdefault(find(fid), []).append(fid)
    return [sorted(v) for v in groups.values()]


def _story_id(finding_ids: list[str]) -> str:
    h = hashlib.sha256("|".join(sorted(finding_ids)).encode()).hexdigest()
    return f"story_{h[:12]}"


def _uniq_join(values, sep: str = ",", cap: int = 0) -> str:
    seen: list[str] = []
    for v in values:
        v = str(v).strip()
        if v and v not in seen:
            seen.append(v)
    if cap:
        seen = seen[:cap]
    return sep.join(seen)


def _max_sev(sevs) -> str:
    return min((s for s in sevs), key=lambda s: _SEV_ORDER.get(s, 9), default="")


def _minmax_seen(findings: list[dict]) -> tuple[str, str]:
    firsts = [f.get("first_seen") or "" for f in findings if f.get("first_seen")]
    lasts = [f.get("last_seen") or "" for f in findings if f.get("last_seen")]
    return (min(firsts) if firsts else ""), (max(lasts) if lasts else "")


def assemble_storyline(members: list[dict], links: list[dict]) -> dict:
    """Roll a group of member findings up into one storyline row."""
    ents = [extract_entities(f) for f in members]
    ips = _uniq_join((ip for e in ents for ip in e["ip"]), cap=50)
    asns = _uniq_join((a for e in ents for a in e["asn"]), sep="; ", cap=20)
    countries = _uniq_join(c for f in members for c in _split(f.get("countries_sample"), ","))
    ip_union = len({ip for e in ents for ip in e["ip"]})

    member_ids = {f["finding_id"] for f in members}
    inner = [ln for ln in links
             if ln["finding_a"] in member_ids and ln["finding_b"] in member_ids]
    link_counts: dict[str, int] = {}
    for ln in inner:
        for etype in json.loads(ln["shared"]):
            link_counts[etype] = link_counts.get(etype, 0) + 1
    first_seen, last_seen = _minmax_seen(members)

    return {
        "storyline_id":     _story_id([f["finding_id"] for f in members]),
        "finding_count":    len(members),
        "finding_ids":      json.dumps(sorted(member_ids), separators=(",", ":")),
        "pattern_ids":      _uniq_join(f["pattern_id"] for f in members),
        "severity":         _max_sev(f.get("severity", "") for f in members),
        "categories":       _uniq_join(f.get("category", "") for f in members),
        "src_ip_count":     ip_union,
        "src_ips_sample":   ips,
        "asns_sample":      asns,
        "countries_sample": countries,
        "linking_entities": json.dumps(link_counts, separators=(",", ":")),
        "link_weight_total": round(sum(ln["weight"] for ln in inner), 2),
        "first_seen":       first_seen,
        "last_seen":        last_seen,
        "detected_at":      _dt.datetime.now(_dt.timezone.utc),
    }


def build_storylines(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Top-level pure transform: findings -> (storyline rows, link rows).

    Storylines are sorted: multi-finding first, then by severity, then size.
    """
    links = build_links(findings)
    by_id = {f["finding_id"]: f for f in findings}
    groups = fuse(list(by_id.keys()), links)
    stories = [assemble_storyline([by_id[fid] for fid in g], links) for g in groups]
    stories.sort(key=lambda s: (
        s["finding_count"] < 2,                       # multi-finding storylines first
        _SEV_ORDER.get(s["severity"], 9),
        -int(s["finding_count"]),
        -int(s["src_ip_count"]),
    ))
    return stories, links


# ----------------------------------------------------------------------
# Stage entry point
# ----------------------------------------------------------------------
def _load_findings() -> list[dict]:
    findings_path = lib.OUTPUT_DIR / "conclusions" / "findings.parquet"
    if not findings_path.exists():
        return []
    con = lib.duck()
    cols = [d[0] for d in con.execute(
        f"DESCRIBE SELECT * FROM read_parquet('{findings_path}')").fetchall()]
    rows = con.execute(
        f"SELECT * FROM read_parquet('{findings_path}')").fetchall()
    con.close()
    findings = [dict(zip(cols, r)) for r in rows]

    # Attach the FULL per-finding source-IP membership (correlate's
    # finding_members.parquet) so IP linking uses complete sets, not the 25-IP
    # display sample.  Absent (older runs) -> extract_entities falls back to the
    # sample automatically.
    members_path = lib.OUTPUT_DIR / "conclusions" / "finding_members.parquet"
    if members_path.exists():
        con = lib.duck()
        mrows = con.execute(
            "SELECT finding_id, src_ip FROM "
            f"read_parquet('{members_path}')").fetchall()
        con.close()
        by_id: dict[str, set[str]] = {}
        for fid, ip in mrows:
            if ip:
                by_id.setdefault(fid, set()).add(ip)
        for f in findings:
            if f["finding_id"] in by_id:
                f["_full_ips"] = by_id[f["finding_id"]]
    return findings


def _render_md(stories: list[dict], summary: dict) -> str:
    multi = [s for s in stories if s["finding_count"] >= 2]
    ratio = summary["finding_consolidation_ratio"]
    ratio_str = f"{ratio:.2f}" if ratio is not None else "n/a"
    lines = [
        "# Threat Storylines (KG-lite finding fusion)", "",
        f"_{summary['n_findings']} findings fused into {summary['n_storylines']} "
        f"storylines ({summary['n_multi_finding']} multi-finding); "
        f"consolidation ratio {ratio_str}._", "",
        "A storyline groups findings that share a strong entity (compositeprint "
        "core_hash, packet chain, source IP, or — corroborated — ASN), so the same "
        "operator's separate signals read as one campaign.", "",
    ]
    if not multi:
        lines += ["_No multi-finding storylines this run — every finding is "
                  "currently independent under the linking threshold._", ""]
    for s in multi:
        lines += [
            f"## {s['severity'].upper()} — storyline `{s['storyline_id']}` "
            f"({s['finding_count']} findings)", "",
            f"_patterns: {s['pattern_ids']} — bound by: "
            f"{s['linking_entities']} — sources: {s['src_ip_count']}_", "",
        ]
        if s["asns_sample"]:
            lines += [f"**ASNs:** {s['asns_sample']}", ""]
        if s["src_ips_sample"]:
            ips = s["src_ips_sample"].split(",")
            shown = ", ".join(f"`{ip}`" for ip in ips[:10])
            more = f" (+{len(ips) - 10} more)" if len(ips) > 10 else ""
            lines += [f"**Representative IPs:** {shown}{more}", ""]
        lines += ["---", ""]
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    findings = _load_findings()

    stories, links = build_storylines(findings)
    n_multi = sum(1 for s in stories if s["finding_count"] >= 2)
    # Membership provenance: how many findings carried full member sets vs only
    # the display sample (aggregate findings with no per-IP detail carry none).
    n_with_full = sum(1 for f in findings if f.get("_full_ips") is not None)
    total_member_ips = sum(len(f.get("_full_ips") or ()) for f in findings)
    summary = {
        "n_findings":       len(findings),
        "n_storylines":     len(stories),
        "n_multi_finding":  n_multi,
        "n_links":          len(links),
        # lower = more fusion; 1.0 means nothing fused.  null when no findings.
        "finding_consolidation_ratio":
            round(len(stories) / len(findings), 4) if findings else None,
        "multi_finding_storyline_share":
            round(sum(s["finding_count"] for s in stories if s["finding_count"] >= 2)
                  / len(findings), 4) if findings else None,
        "largest_storyline_findings":
            max((s["finding_count"] for s in stories), default=0),
        "findings_with_full_membership": n_with_full,
        "total_member_ips_linked": total_member_ips,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
    }

    pq.write_table(pa.Table.from_pylist(stories, schema=STORYLINE_SCHEMA),
                   OUT_DIR / "storylines.parquet",
                   compression="zstd", compression_level=3)
    pq.write_table(pa.Table.from_pylist(links, schema=LINK_SCHEMA),
                   OUT_DIR / "finding_links.parquet",
                   compression="zstd", compression_level=3)
    (OUT_DIR / "storylines.md").write_text(_render_md(stories, summary))
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2))

    print(f"[kg] linked on full membership: {n_with_full}/{len(findings)} findings "
          f"carry per-IP members ({total_member_ips:,} member IPs total)",
          file=sys.stderr)
    print(f"[kg] {len(findings)} findings -> {len(stories)} storylines "
          f"({n_multi} multi-finding, {len(links)} links) -> {OUT_DIR}",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    return run(argparse.Namespace())


if __name__ == "__main__":
    sys.exit(main())

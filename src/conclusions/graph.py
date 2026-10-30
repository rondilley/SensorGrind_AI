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
      -> extract entities per finding (IPs, ASNs, core_hash, chain), plus
         port / payload / day / l7 derived from the members' packets
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
    "payload":   4.0,   # same payload bytes (sha256) on the same port, most members
    "ip":        3.0,   # same source host
    "asn":       1.5,   # same network — weak; needs corroboration to count
    "port":      1.5,   # same proto/dst_port hit by most members — weak alone
    "day":       1.5,   # same UTC activity day (short findings only) — weak alone
    "l7":        0.5,   # same l7 protocol label — corroboration only
}

# Entity types derived from the members' own packets (derive_entities), not
# from what the pattern wrote.  They let findings of DIFFERENT analyzers meet:
# an HDC flag group, a LIF flag group and a chain finding about the same swarm
# share no fingerprint key, but their members hit the same port with the same
# payload on the same days.  port + day (3.0) is enough to link; a shared
# payload is enough alone.
DERIVED_TYPES = ("port", "l7", "payload", "day")
DERIVED_MIN_SHARE = 0.5        # value must cover >= this share of active members
DERIVED_MAX_VALUES = 5         # keep the top values of each type per finding
DAY_MAX_SPAN_D = 7             # day entities only for findings this short
# A derived value carried by more findings than this is a hub (port 22, http,
# the empty-ish payloads of mass scanners) and is dropped from linking, the
# same idea as the MIN_EDGE_WEIGHT guard for a hub ASN.
DERIVED_HUB_MAX_FINDINGS = 8

# A finding pair is only linked if its summed shared-entity weight reaches this.
# 3.0 = one shared IP, or one core_hash/chain, or >=2 shared ASNs.  A single
# shared ASN (1.5) is below the bar, so a hub ASN cannot fuse the graph.
MIN_EDGE_WEIGHT = 3.0

# Cap how many shared entities of one type count toward an edge weight.  Two
# findings sharing 5,000 IPs are already maximally linked; without a cap that
# one edge's raw weight would swamp the Louvain partition.  (Thresholding and
# the displayed shared sample are unaffected.)
WEIGHT_COUNT_CAP = 50

# Shared IPs link two findings only when they are a real part of the smaller
# finding: at least this share of its member set.  One shared IP is enough for
# two small findings, but the l7 / landscape / miner facts hold thousands of
# residential peers, and one IP in common with a 15,000-member set is chance.
IP_MIN_CONTAINMENT = 0.05
# ... and at least this share of the LARGER set: a 4-source chain finding that
# shares 1 IP with a 15,000-source swarm is 25 % of the chain but chance.
IP_MIN_SHARE_OF_LARGER = 0.001

# Known scanners (scannerintel benign_org: zgrab, Censys, Shodan, Expanse, ...,
# plus every source in a benignfilter.SCANNER_ASNS ASN, so a change of that
# list takes effect here before benignfilter runs again)
# send to every port, thus they are in the member sets of most findings and an
# IP link through them says nothing about a shared operator.  They are removed
# from the IP entity only: they keep their findings, flags and risk.  With
# SCANNER_EXCLUDE_BEHAVIORAL, every portscans source (>= 10 ports) is removed
# too; on the 2026-10-28 corpus that made the largest HTTP/scanner storyline
# 18 findings in place of 28.  Some of those sources are botnet hosts whose
# overlap is a real link; the operator turned it on 2026-10-28.
SCANNER_EXCLUDE_KNOWN = True
SCANNER_EXCLUDE_BEHAVIORAL = True

# derive_entities reads the packets of at most this many members per finding
# (a fixed hash sample); the 50 % share of a value is stable at this size.
DERIVED_SAMPLE = 2000

# BitTorrent handshake facts for the storyline prompt: the plaintext 68-byte
# handshake (pstrlen 19) carries the protocol string, the infohash and the
# sender's peer ID, whose first 8 bytes name the client.  conclude gets these
# so it can tell a P2P swarm from a flood that only uses the BitTorrent ports.
BT_L7_ID = lib.L7_ID["bittorrent"]
BT_MIN_SOURCES = 10            # fewer handshake senders than this: no facts
BT_MIN_SHARE = 0.25            # nor under this share of the sampled sources,
                               # so a few P2P hosts in an HTTP finding say nothing
BT_TOP = 5                     # protocol strings / peer-ID prefixes / ports kept

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
    ("handshake_facts",  pa.string()),   # JSON {finding_id: BitTorrent facts}
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
    # Derived from the member packets by derive_entities() in run(); absent in
    # pure unit tests that pass a bare finding dict.
    derived = finding.get("_derived") or {}
    for etype in DERIVED_TYPES:
        ents[etype] = set(derived.get(etype, ()))
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


def derived_hubs(ents: list[dict[str, set[str]]]) -> dict[str, set[str]]:
    """Derived entity values carried by more than DERIVED_HUB_MAX_FINDINGS findings."""
    hubs: dict[str, set[str]] = {}
    for etype in DERIVED_TYPES:
        count: dict[str, int] = {}
        for e in ents:
            for v in e.get(etype, ()):
                count[v] = count.get(v, 0) + 1
        hubs[etype] = {v for v, c in count.items() if c > DERIVED_HUB_MAX_FINDINGS}
    return hubs


def _shared(a: dict[str, set[str]], b: dict[str, set[str]]) -> dict[str, list[str]]:
    """Entities the two findings have in common, by type (non-empty types only)."""
    out: dict[str, list[str]] = {}
    for etype in ENTITY_WEIGHTS:
        common = a.get(etype, set()) & b.get(etype, set())
        if etype == "ip" and common:
            smaller, larger = sorted((len(a["ip"]), len(b["ip"])))
            if (len(common) < IP_MIN_CONTAINMENT * smaller
                    or len(common) < IP_MIN_SHARE_OF_LARGER * larger):
                continue
        if common:
            out[etype] = sorted(common)
    return out


def _edge_weight(shared: dict[str, list[str]]) -> float:
    # A derived type counts once: two shared ports (22 and 2222) or three
    # shared days of one burst are one fact, not two or three.
    return sum(ENTITY_WEIGHTS[etype]
               * min(len(vals), 1 if etype in DERIVED_TYPES else WEIGHT_COUNT_CAP)
               for etype, vals in shared.items())


def build_links(findings: list[dict],
                exclude_ips: frozenset[str] = frozenset()) -> list[dict]:
    """Every finding pair whose shared-entity weight clears MIN_EDGE_WEIGHT.

    Each link row carries the pair, the summed weight, and a capped sample of the
    shared entity values (for the report + transparency).
    """
    ents = [extract_entities(f) for f in findings]
    if exclude_ips:
        for e in ents:
            e["ip"] -= exclude_ips
    hubs = derived_hubs(ents)
    for e in ents:
        for etype, vals in hubs.items():
            e[etype] -= vals
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
    bt = {f["finding_id"]: f["_bt"] for f in members if f.get("_bt")}

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
        "handshake_facts":  json.dumps(bt, sort_keys=True, separators=(",", ":"))
                            if bt else None,
        "detected_at":      _dt.datetime.now(_dt.timezone.utc),
    }


def build_storylines(findings: list[dict],
                     exclude_ips: frozenset[str] = frozenset()
                     ) -> tuple[list[dict], list[dict]]:
    """Top-level pure transform: findings -> (storyline rows, link rows).

    Storylines are sorted: multi-finding first, then by severity, then size.
    """
    links = build_links(findings, exclude_ips)
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


def load_scanner_ips() -> frozenset[str]:
    """The scanner IPs that IP links ignore (see SCANNER_EXCLUDE_*)."""
    parts = []
    si = lib.REPORTS / "scannerintel" / "scannerintel.parquet"
    if SCANNER_EXCLUDE_KNOWN and si.exists():
        from benignfilter import SCANNER_ASNS
        asns = ",".join(str(int(a)) for a in SCANNER_ASNS)
        parts.append(f"SELECT src_ip FROM read_parquet('{si.as_posix()}') "
                     "WHERE (benign_org IS NOT NULL AND benign_org <> '') "
                     f"OR asn IN ({asns})")
    ps = lib.REPORTS / "portscans" / "portscans.parquet"
    if SCANNER_EXCLUDE_BEHAVIORAL and ps.exists():
        parts.append(f"SELECT src_ip FROM read_parquet('{ps.as_posix()}')")
    if not parts:
        return frozenset()
    con = lib.duck()
    try:
        rows = con.execute(" UNION ".join(parts)).fetchall()
    finally:
        con.close()
    return frozenset(r[0] for r in rows if r[0])


def _utc_day(s: str | None) -> _dt.date | None:
    """UTC date of a finding's first_seen / last_seen string ('' -> None)."""
    if not s:
        return None
    try:
        if len(s) == 10:
            return _dt.date.fromisoformat(s)
        t = _dt.datetime.fromisoformat(s)
        if t.tzinfo is None:
            return t.date()
        return t.astimezone(_dt.timezone.utc).date()
    except ValueError:
        return None


def pick_values(counts: dict[str, int], active: int) -> list[str]:
    """The derived values that characterize a finding.

    ``counts`` maps a value to the number of members that had it; ``active``
    is the number of members with any packet in the finding window.  A value
    counts when it covers DERIVED_MIN_SHARE of the active members (and at
    least 2 of them, unless the finding has 1 member).  Top DERIVED_MAX_VALUES.
    """
    if active <= 0:
        return []
    need = min(2, active)
    keep = [(k, v) for v, k in counts.items()
            if k >= need and k / active >= DERIVED_MIN_SHARE]
    keep.sort(key=lambda kv: (-kv[0], kv[1]))
    return [v for _, v in keep[:DERIVED_MAX_VALUES]]


def derive_entities(findings: list[dict]) -> dict[str, int]:
    """Attach ``_derived`` {type: [values]} to each finding with full members.

    One join of the member IPs with the packets in each finding's window
    (UTC days from first_seen to last_seen; no window = all days).  Uses the
    clustered packets when they exist (a few seconds on the full corpus).
    Returns the number of findings that got each derived type.
    """
    rows = []
    for f in findings:
        ips = f.get("_full_ips")
        if not ips:
            continue
        lo, hi = _utc_day(f.get("first_seen")), _utc_day(f.get("last_seen"))
        if lo and hi and lo > hi:
            lo, hi = hi, lo
        short = bool(lo and hi and (hi - lo).days <= DAY_MAX_SPAN_D)
        if len(ips) > DERIVED_SAMPLE:
            ips = sorted(ips, key=lambda ip: hashlib.sha1(ip.encode()).digest())
            ips = ips[:DERIVED_SAMPLE]
        rows += [{"finding_id": f["finding_id"], "src_ip": ip,
                  "lo": lo, "hi": hi, "short": short} for ip in ips]
    stats = {t: 0 for t in DERIVED_TYPES}
    if not rows:
        return stats
    mem = pa.Table.from_pylist(rows, schema=pa.schema([
        ("finding_id", pa.string()), ("src_ip", pa.string()),
        ("lo", pa.date32()), ("hi", pa.date32()), ("short", pa.bool_())]))
    con = lib.duck()
    try:
        lib.register_views(con, clustered=True)
        con.register("mem", mem)
        con.execute("""
            CREATE TEMP TABLE hits AS
            SELECT m.finding_id, p.src_ip, p.proto, p.dst_port,
                   CASE WHEN p.payload_len > 0 THEN p.payload_sha256 END AS payload,
                   p.l7_proto, p.dt, m.short
            FROM packets p JOIN mem m ON p.src_ip = m.src_ip
            WHERE (m.lo IS NULL OR p.dt >= m.lo) AND (m.hi IS NULL OR p.dt <= m.hi)
            GROUP BY ALL
        """)
        active = dict(con.execute(
            "SELECT finding_id, count(DISTINCT src_ip) FROM hits GROUP BY 1").fetchall())
        value_sql = {
            "port":    ("CASE proto WHEN 6 THEN 'tcp/' WHEN 17 THEN 'udp/' END "
                        "|| dst_port", "proto IN (6, 17) AND dst_port IS NOT NULL"),
            # The payload together with its port: a generic payload (the
            # BitTorrent keep-alive, an HTTP GET /) is a hub alone, but the
            # same bytes on the same unusual port is a specific fact.
            "payload": ("CASE proto WHEN 6 THEN 'tcp/' WHEN 17 THEN 'udp/' END "
                        "|| dst_port || ':' || lower(hex(payload))",
                        "payload IS NOT NULL AND proto IN (6, 17) "
                        "AND dst_port IS NOT NULL"),
            "l7":      ("CAST(l7_proto AS INTEGER)", "l7_proto > 0"),
            "day":     ("CAST(dt AS VARCHAR)", "short"),
        }
        per: dict[str, dict[str, dict[str, int]]] = {}
        for etype, (expr, cond) in value_sql.items():
            for fid, v, k in con.execute(f"""
                SELECT finding_id, {expr} AS v, count(DISTINCT src_ip) AS k
                FROM hits WHERE {cond} GROUP BY 1, 2
            """).fetchall():
                if etype == "l7":
                    v = lib.L7_NAME.get(int(v), str(v))
                per.setdefault(fid, {}).setdefault(etype, {})[str(v)] = int(k)
        bt = bt_facts(con, active)
    finally:
        con.close()
    for f in findings:
        if f["finding_id"] in bt:
            f["_bt"] = bt[f["finding_id"]]
    stats["bittorrent_facts"] = len(bt)
    for f in findings:
        counts = per.get(f["finding_id"])
        if not counts:
            continue
        n = active.get(f["finding_id"], 0)
        f["_derived"] = {t: pick_values(counts.get(t, {}), n) for t in DERIVED_TYPES}
        for t in DERIVED_TYPES:
            stats[t] += bool(f["_derived"][t])
    return stats


def _pstr_name(hx: str) -> str:
    """The 19-byte protocol string as text, or 'custom <hex>' if not ASCII."""
    raw = bytes.fromhex(hx)
    if all(32 <= c < 127 for c in raw):
        return raw.decode()
    return "custom " + hx.lower()


def _peer_prefix(hx: str) -> str:
    """The first 8 peer-ID bytes as text, or 'hex <hex>' if not ASCII."""
    raw = bytes.fromhex(hx)
    if all(32 <= c < 127 for c in raw):
        return raw.decode()
    return "hex " + hx.lower()


def bt_facts(con, active: dict[str, int]) -> dict[str, dict]:
    """Per finding: what the plaintext BitTorrent handshakes in the members'
    packets (the ``hits`` temp table) say.  Counts are distinct sources in the
    DERIVED_SAMPLE member sample."""
    con.execute(f"""
        CREATE TEMP TABLE bt AS
        SELECT h.finding_id, h.src_ip, h.proto, h.dst_port,
               substr(b.hx, 3, 38) AS pstr, substr(b.hx, 57, 40) AS infohash,
               substr(b.hx, 97, 16) AS peer
        FROM (SELECT DISTINCT finding_id, src_ip, proto, dst_port, payload
              FROM hits WHERE l7_proto = {BT_L7_ID} AND payload IS NOT NULL) h
        JOIN (SELECT DISTINCT payload_sha256, hex(bytes) AS hx FROM payload_blobs
              WHERE l7_proto = {BT_L7_ID} AND payload_len = 68
                AND starts_with(hex(bytes), '13')) b
          ON h.payload = b.payload_sha256
    """)
    out: dict[str, dict] = {}
    for fid, n, n_hash in con.execute("""
        SELECT finding_id, count(DISTINCT src_ip), count(DISTINCT infohash)
        FROM bt GROUP BY 1
    """).fetchall():
        if n >= BT_MIN_SOURCES and n >= BT_MIN_SHARE * active.get(fid, 0):
            out[fid] = {"handshake_sources": int(n),
                        "sampled_sources": int(active.get(fid, 0)),
                        "infohashes": int(n_hash)}
    if not out:
        return out
    tops = {
        "protocol_strings": ("pstr", "TRUE", _pstr_name),
        "peer_id_prefixes": ("peer", "TRUE", _peer_prefix),
        "ports": ("CASE proto WHEN 6 THEN 'tcp/' WHEN 17 THEN 'udp/' END "
                  "|| dst_port", "dst_port IS NOT NULL", str),
    }
    for key, (expr, cond, fmt) in tops.items():
        for fid, v, k in con.execute(f"""
            SELECT finding_id, v, k FROM (
                SELECT finding_id, {expr} AS v, count(DISTINCT src_ip) AS k,
                       row_number() OVER (PARTITION BY finding_id
                                          ORDER BY count(DISTINCT src_ip) DESC,
                                                   {expr}) AS r
                FROM bt WHERE {cond} GROUP BY 1, 2)
            WHERE r <= {BT_TOP} ORDER BY finding_id, k DESC, v
        """).fetchall():
            if fid in out:
                out[fid].setdefault(key, []).append([fmt(v), int(k)])
    return out


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
        "core_hash, packet chain, payload, source IP, or — corroborated — ASN, "
        "port, activity day, l7 protocol), so the same operator's separate "
        "signals read as one campaign.  Payload, port, day and l7 come from the "
        "members' own packets, which lets findings of different analyzers "
        "(for example a neuromorphic flag group and a chain finding) meet.", "",
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
    derived_stats = derive_entities(findings)
    scanners = load_scanner_ips()
    member_ips = {ip for f in findings for ip in (f.get("_full_ips") or ())}
    n_scanner_members = len(member_ips & scanners)

    stories, links = build_storylines(findings, scanners)
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
        # findings that got each derived entity type from their member packets
        "findings_with_derived": derived_stats,
        # scanner IPs left out of IP links (they stay in the member sets)
        "scanner_ips_excluded_from_links": n_scanner_members,
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
    print(f"[kg] derived entities (findings with each type): {derived_stats}",
          file=sys.stderr)
    print(f"[kg] {n_scanner_members:,} member IPs are known scanners "
          f"(of {len(scanners):,}); IP links ignore them", file=sys.stderr)
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

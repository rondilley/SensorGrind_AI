#!/usr/bin/env python3
"""
conclusions/verdict - deterministic verdict for each correlator finding.

The correlator (correlate.py) says WHAT pattern fired.  This stage says what
the pattern MEANS, from facts only, with no LLM:

  1. Facts.  For each finding, measure its full member-source set
     (finding_members.parquet) against tool outputs: the L7 protocol share
     (l7_events), the known-scanner share (benignfilter), the botnet-payload
     and bulletproof-hosting shares (risk rationale).  Add the port, service,
     L7 protocol and HTTP request template that the correlator put in
     key_metrics.

  2. Rules.  An ordered rule table (RULES) maps facts to one verdict.  The
     first rule that fires gives the verdict; every rule that fires is kept in
     `also_matched` so a conflict is visible.  No rule fires -> `unclassified`.
     The tool does not guess.

Each verdict row carries the rule id, the ATT&CK technique, a one-line reason
that quotes the numbers that made the rule fire, and the facts JSON.  The same
inputs always give the same output (no timestamps, sorted rows, rounded
shares), so a verdict can be checked and pinned by a test.

Outputs
-------
  output/conclusions/verdicts.parquet   one row per finding
  output/conclusions/problems.parquet   findings with the same verdict and
                                        target merged into one problem
  output/conclusions/verdicts.md        problem table, then one line per finding

The LLM narrative stage (synthesize.py) is opt-in; it is not needed here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib
from conclusions import correlate


OUT_DIR = lib.OUTPUT_DIR / "conclusions"
BENIGN_PATH = lib.REPORTS / "benignfilter" / "benignfilter.parquet"
ASNINTEL_PATH = lib.REPORTS / "asnintel" / "asnintel.parquet"

# Share thresholds.  On the 2026-10-29 corpus the member BitTorrent share of a
# finding is either >= 0.74 or <= 0.25, so 0.5 sits in the empty gap; the
# other shares use the same majority rule.
BT_SHARE = 0.5
SCANNER_SHARE = 0.5
BOTNET_SHARE = 0.5
BULLETPROOF_SHARE = 0.5
L7_SHARE = 0.5
# Fewer member sources than this: the verdict is marked basis=sample.  Also
# the least number of non-scanner members that must send HTTP credentials
# before http_credentials fires (an absolute count: credential use is
# evidence at any share; the reason line gives the share).
MIN_SUPPORT = 10
# Least share of members that must send HTTP credentials for the whole finding
# to be a credential attack.  On the 2026-10-29 corpus the shares are 11.3%,
# 6.0%, then <= 3%; below this the credential senders go in `note` (a subset,
# not the finding's verdict).
CRED_SHARE = 0.10

# Ports of services that are not in correlate.L7_STD_PORTS (which is keyed by
# the parser's L7 names).  A port maps to a service name only through these
# two tables.
EXTRA_PORTS: dict[str, frozenset[int]] = {
    "vnc":      frozenset(range(5900, 5904)),
    "mssql":    frozenset({1433}),
    "mysql":    frozenset({3306}),
    "postgres": frozenset({5432}),
    "sip":      frozenset({5060, 5061}),
    "coap":     frozenset({5683, 5684}),
    "docker":   frozenset({2375, 2376}),
    "ipp":      frozenset({631}),
    "bgp":      frozenset({179}),
}
SERVICE_PORTS = {**correlate.L7_STD_PORTS, **EXTRA_PORTS}

# Services where a successful login gives access.  A probe of one of these
# with no credential material is still recon, not a credential attack.
AUTH_SERVICES = frozenset({"ssh", "telnet", "rdp", "vnc", "ftp", "smb",
                           "mssql", "mysql", "postgres", "redis", "mongo"})
# Services where the server must speak first (greeting, banner or key
# exchange) before a client can log in.  The sensor only completes the TCP
# handshake, so a login on these is never visible: on the 2026-10-29 corpus
# the parser has 0 telnet, vnc and ftp events, and ssh shows only client
# banners.  A credential verdict on these services has no evidence here.
SERVER_FIRST = frozenset({"ssh", "telnet", "vnc", "ftp", "smtp", "mysql",
                          "postgres", "mssql"})

# key_metrics keys that hold a finding's full source population.
POPULATION_KEYS = ("n_ips", "source_count", "members", "n_sources",
                   "rule_ip_count", "distinct_ips", "src_ip_count")

# HTTP request templates (httppatterns cluster heads) -> what they target.
# Order matters: the first match wins.  `exploit` rows are requests that
# carry an exploit (they change state on a vulnerable target); every other
# row is discovery of an exposed target.
HTTP_TARGETS: list[tuple[str, str, str, str]] = [
    # (regex on template, target, verdict, ATT&CK technique)
    (r"^POST /wsman", "WS-Management / OMI (CVE-2021-38647)",
     "exploit_attempt", "T1190"),
    (r"cgi-bin|/shell\?|cmd=|wget|curl|chmod|\$\{jndi|\.\./|eval-stdin|"
     r"/HNAP1|GponForm|boaform|setup\.cgi",
     "command-injection URL", "exploit_attempt", "T1190"),
    (r"/manager/(html|text)", "Tomcat Manager", "service_recon", "T1595.003"),
    (r"/containers/json", "Docker Engine API", "service_recon", "T1595.003"),
    (r"/\.env\b|/\.git/config", "exposed secrets file (.env / .git)",
     "service_recon", "T1595.003"),
    (r"/xmrig", "XMRig miner API", "service_recon", "T1595.003"),
    (r"^CONNECT ", "open HTTP proxy", "service_recon", "T1595.002"),
    (r"^POST /ipp", "IPP printing service", "service_recon", "T1595.002"),
    (r"^OPTIONS /sip:", "SIP endpoint", "service_recon", "T1595.002"),
    (r"/version$", "API version endpoint", "service_recon", "T1595.002"),
    (r"/login", "web login page", "service_recon", "T1595.003"),
    (r".", "web path", "service_recon", "T1595.003"),
]

# Correlator patterns whose own test is the fact (no member facts needed).
RECON_PATTERNS = {
    "wrong_proto_for_port": "wrong-transport probes of well-known ports",
    "telco_ss7_recon": "SIGTRAN / SIP telco ports",
    "ipsec_probe_from_scanner": "IPsec (ESP/AH)",
    "low_slow_subnet_coordinated": "low-and-slow subnet scan",
}
ANOMALY_PATTERNS = {
    "icmp_payload_anomalies": "ICMP with payload",
    "covert_tunnel_setup": "GRE / IP-in-IP tunnel packets",
    "tcp_midstream_or_syn_payload": "TCP state-machine violations",
}

ACTIONS = {
    "benign_p2p": "Suppress. P2P peers (BitTorrent, Monero) that use a stale "
                  "peer-list address; no block needed.",
    "research_scanner": "Tag as known scanner. No alert.",
    "credential_attack": "Block the sources. Make sure the service is not "
                         "exposed with default or reused credentials.",
    "exploit_attempt": "Block the sources. Make sure no exposed host has the "
                       "targeted vulnerability.",
    "service_recon": "No block needed. Make sure the target service is not "
                     "exposed.",
    "hostile_infrastructure": "Review the ASNs for the block list.",
    "protocol_anomaly": "Inspect a packet sample before you act.",
    "context": "No new action. The block-grade ASNs are already in the "
               "asnintel table.",
    "unclassified": "No rule fired. Review the finding, then add a rule.",
}

# Verdicts that ask a defender to act (block / review a block list).
ACT_VERDICTS = ("exploit_attempt", "credential_attack", "hostile_infrastructure")

VERDICT_ORDER = ["exploit_attempt", "credential_attack", "hostile_infrastructure",
                 "service_recon", "protocol_anomaly", "research_scanner",
                 "benign_p2p", "context", "unclassified"]

VERDICT_SCHEMA = pa.schema([
    ("finding_id",   pa.string()),
    ("pattern_id",   pa.string()),
    ("pattern",      pa.string()),
    ("verdict",      pa.string()),
    ("rule_id",      pa.string()),
    ("technique",    pa.string()),
    ("why",          pa.string()),
    ("action",       pa.string()),
    ("basis",        pa.string()),
    ("n_members",    pa.uint32()),
    ("port",         pa.int32()),
    ("service",      pa.string()),
    ("also_matched", pa.string()),
    ("note",         pa.string()),
    ("target",       pa.string()),
    ("facts",        pa.string()),
])

PROBLEM_SCHEMA = pa.schema([
    ("problem_id",     pa.string()),
    ("verdict",        pa.string()),
    ("target",         pa.string()),
    ("action",         pa.string()),
    ("finding_count",  pa.uint32()),
    ("finding_ids",    pa.string()),   # JSON list
    ("sources",        pa.uint32()),   # distinct member sources
    ("population_max", pa.uint32()),   # largest finding population (sampled)
    ("ports",          pa.string()),
    ("detail",         pa.string()),   # HTTP templates, botnet families
    ("rules",          pa.string()),
    ("techniques",     pa.string()),
    ("first_seen",     pa.string()),
    ("last_seen",      pa.string()),
    ("note",           pa.string()),
])


def pattern_family(pattern_id: str) -> str:
    """Strip the hash / port suffix the correlator adds to a pattern id."""
    return re.sub(r"_[0-9a-f]{8,12}$|_[0-9]+$", "", pattern_id)


def _port_of(km: dict) -> int | None:
    for k in ("rep_port", "port"):
        if isinstance(km.get(k), int):
            return km[k]
    top = km.get("top_dst_ports")
    if isinstance(top, str) and top:
        head = top.split(",")[0].split(":")[0]
        if head.isdigit():
            return int(head)
    return None


def _service_of(port: int | None, km_l7: str | None) -> str | None:
    if km_l7 and km_l7 not in ("unknown", "bittorrent"):
        return km_l7
    if port is None:
        return None
    for name, ports in SERVICE_PORTS.items():
        if port in ports:
            return name
    return None


# ----------------------------------------------------------------------
# Facts
# ----------------------------------------------------------------------

def member_facts(con) -> dict[str, dict]:
    """finding_id -> shares measured over the finding's full member set."""
    members = OUT_DIR / "finding_members.parquet"
    if not members.exists():
        return {}
    con.execute(f"""CREATE OR REPLACE TEMP TABLE m AS
        SELECT DISTINCT finding_id, src_ip FROM read_parquet('{members}')""")
    out: dict[str, dict] = {
        fid: {"n_members": int(n), "l7_share": {}}
        for fid, n in con.execute(
            "SELECT finding_id, count(*) FROM m GROUP BY 1").fetchall()}

    for fid, l7, n in con.execute(f"""
        SELECT m.finding_id, l.l7_proto, count(DISTINCT l.src_ip)
        FROM read_parquet('{lib.L7_GLOB}', hive_partitioning=1) l
        JOIN m USING (src_ip)
        WHERE l.l7_proto <> {lib.L7_ID['unknown']}
        GROUP BY 1, 2""").fetchall():
        f = out[fid]
        f["l7_share"][lib.L7_NAME.get(l7, str(l7))] = round(n / f["n_members"], 4)

    if BENIGN_PATH.exists():
        for fid, n in con.execute(f"""
            SELECT m.finding_id, count(DISTINCT m.src_ip)
            FROM m JOIN read_parquet('{BENIGN_PATH}') b USING (src_ip)
            WHERE b.confidence IN ('high', 'medium')
            GROUP BY 1""").fetchall():
            out[fid]["scanner_share"] = round(n / out[fid]["n_members"], 4)

    # Members that sent an HTTP Authorization header (parser field "auth"),
    # not counting known scanners: they almost never send credentials (1 of
    # ~700 credential senders on the 2026-10-29 corpus).
    scanners = (f"AND src_ip NOT IN (SELECT src_ip FROM read_parquet('{BENIGN_PATH}') "
                f"WHERE confidence IN ('high', 'medium'))"
                if BENIGN_PATH.exists() else "")
    for fid, n in con.execute(f"""
        SELECT m.finding_id, count(DISTINCT l.src_ip)
        FROM read_parquet('{lib.L7_GLOB}', hive_partitioning=1) l
        JOIN m USING (src_ip)
        WHERE l.l7_proto = {lib.L7_ID['http']}
          AND l.fields_json LIKE '%"auth":%' {scanners}
        GROUP BY 1""").fetchall():
        out[fid]["http_auth_sources"] = int(n)

    # Per-IP features (newest snapshot): the members' most common top port,
    # its share, and the mean SYN-only share of their packets.
    snap = sf.latest_snapshot("ip", 1)
    if snap:
        fglob = f"{sf.snapshot_dir(snap)}/*.parquet"
        con.execute(f"""CREATE OR REPLACE TEMP TABLE mf AS
            SELECT m.finding_id, f.top_port, f.pct_syn_only
            FROM m JOIN read_parquet('{fglob}') f USING (src_ip)""")
        for fid, port, k in con.execute("""
            SELECT finding_id, top_port, k FROM (
                SELECT finding_id, top_port, count(*) AS k,
                       row_number() OVER (PARTITION BY finding_id
                                          ORDER BY count(*) DESC, top_port) AS r
                FROM mf WHERE top_port IS NOT NULL GROUP BY 1, 2)
            WHERE r = 1""").fetchall():
            out[fid]["member_top_port"] = int(port)
            out[fid]["member_top_port_share"] = round(k / out[fid]["n_members"], 4)
        for fid, syn in con.execute("""
            SELECT finding_id, avg(pct_syn_only) FROM mf GROUP BY 1""").fetchall():
            if syn is not None:
                out[fid]["member_syn_only"] = round(float(syn), 4)

    risk = correlate._newest_risk_path()
    if risk:
        con.execute(f"""CREATE OR REPLACE TEMP TABLE mr AS
            SELECT m.finding_id, r.rationale
            FROM m JOIN read_parquet('{risk}') r USING (src_ip)""")
        for fid, bot, bp in con.execute("""
            SELECT finding_id,
                   count(*) FILTER (WHERE rationale LIKE '%botnet=%'),
                   count(*) FILTER (WHERE rationale LIKE '%infra=bulletproof%')
            FROM mr GROUP BY 1""").fetchall():
            n = out[fid]["n_members"]
            out[fid]["botnet_share"] = round(bot / n, 4)
            out[fid]["bulletproof_share"] = round(bp / n, 4)
        # Most common family; ties go to the first name, not to mode()'s
        # arbitrary pick (which made reruns differ).
        for fid, fam in con.execute("""
            SELECT finding_id, fam FROM (
                SELECT finding_id,
                       regexp_extract(rationale, 'botnet=([a-z_]+)', 1) AS fam,
                       row_number() OVER (PARTITION BY finding_id
                                          ORDER BY count(*) DESC, fam) AS r
                FROM mr WHERE rationale LIKE '%botnet=%' GROUP BY 1, 2)
            WHERE r = 1""").fetchall():
            out[fid]["botnet_family"] = fam
    return out


def asn_table(con) -> dict[int, tuple[bool, str]]:
    """asn -> (asnintel bulletproof_flag, risk_grade)."""
    if not ASNINTEL_PATH.exists():
        return {}
    return {int(a): (bool(bp), g or "") for a, bp, g in con.execute(f"""
        SELECT asn, bulletproof_flag, risk_grade
        FROM read_parquet('{ASNINTEL_PATH}')""").fetchall()}


def _asn_list(km: dict) -> list[int]:
    """The ASNs an ASN-level finding names in key_metrics["asns"]: either
    "AS123" strings or {"asn": 123, ...} rows."""
    out = []
    for a in km.get("asns") or []:
        v = str(a.get("asn") if isinstance(a, dict) else a).removeprefix("AS")
        if v.isdigit():
            out.append(int(v))
    return out


def finding_facts(f: dict, mf: dict | None,
                  asns: dict[int, tuple[bool, str]] | None = None) -> dict:
    try:
        km = json.loads(f.get("key_metrics") or "{}")
    except (ValueError, TypeError):
        km = {}
    port = _port_of(km)
    km_l7 = km.get("l7") if isinstance(km.get("l7"), str) else None
    facts = {
        "pattern": pattern_family(f["pattern_id"]),
        "port": port,
        "service": _service_of(port, km_l7),
        "km_l7": km_l7,
        "http_template": km.get("template") if isinstance(km.get("template"), str) else None,
        "n_members": 0,
        "l7_share": {},
        "scanner_share": 0.0,
        "botnet_share": 0.0,
        "bulletproof_share": 0.0,
        "botnet_family": None,
        "http_auth_sources": 0,
        "population": max([v for k in POPULATION_KEYS
                           if isinstance(v := km.get(k), int)], default=0),
        "asn_count": 0,
        "asn_known": 0,
        "asn_bulletproof_share": 0.0,
        "asn_block_grade": 0,
        "member_top_port": None,
        "member_top_port_share": 0.0,
        "member_syn_only": 0.0,
        "port_from": "correlator" if port is not None else None,
        "port_p2p_findings": 0,
    }
    listed = _asn_list(km)
    if listed:
        known = [asns[a] for a in listed if a in (asns or {})]
        facts["asn_count"] = len(listed)
        facts["asn_known"] = len(known)
        if known:
            facts["asn_bulletproof_share"] = round(
                sum(bp for bp, _g in known) / len(known), 4)
            facts["asn_block_grade"] = sum(g == "block_asn" for _bp, g in known)
    if f["pattern_id"] == "rdp_credential_spray":
        top = (km.get("top") or [{}])[0]
        facts["rdp_cookie"] = top.get("mstshash")
        facts["rdp_cookie_sources"] = top.get("src_ip_count")
    if mf:
        facts.update(mf)
    # No port from the correlator: use the members' top port when most of
    # them share it (the LIF groups and the arrival burst have no port).
    if facts["port"] is None and facts["member_top_port_share"] >= L7_SHARE:
        facts["port"] = facts["member_top_port"]
        facts["port_from"] = "members"
        facts["service"] = _service_of(facts["port"], km_l7)
    return facts


# ----------------------------------------------------------------------
# Rules
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    rule_id: str
    verdict: str
    technique: str
    # Returns the one-line reason (quoting the facts) when the rule fires,
    # else None.
    test: Callable[[dict], str | None]
    # Facts the rule reads only from members; drives basis=members|sample.
    member_based: bool = True


def _pct(x: float) -> str:
    return "less than 1%" if 0 < x < 0.005 else f"{x:.0%}"


def _bt_members(x):
    s = x["l7_share"].get("bittorrent", 0.0)
    if s >= BT_SHARE and x["scanner_share"] < SCANNER_SHARE:
        return f"{_pct(s)} of {x['n_members']:,} member sources sent BitTorrent traffic"


P2P_L7 = ("bittorrent", "levin")


def _is_p2p_by_members(x: dict) -> bool:
    # Known scanners that send P2P probes (Levin on Monero ports) are
    # scanners, not peers: a scanner-majority finding is never P2P.
    return (x["scanner_share"] < SCANNER_SHARE
            and any(x["l7_share"].get(p, 0.0) >= BT_SHARE for p in P2P_L7))


def _levin_members(x):
    s = x["l7_share"].get("levin", 0.0)
    if s >= BT_SHARE and x["scanner_share"] < SCANNER_SHARE:
        return (f"{_pct(s)} of {x['n_members']:,} member sources sent Levin "
                f"(Monero P2P) traffic")


def _bt_surge(x):
    if x["km_l7"] == "bittorrent":
        return f"the surge on port {x['port']} is BitTorrent traffic"


def _http_credentials(x):
    n = x["http_auth_sources"]
    if n >= MIN_SUPPORT and n / x["n_members"] >= CRED_SHARE:
        return (f"{n:,} of {x['n_members']:,} member sources "
                f"({_pct(n / x['n_members'])}) sent HTTP Authorization "
                f"credentials; none are known scanners")


def _scanner(x):
    s = x["scanner_share"]
    if s >= SCANNER_SHARE:
        return (f"{_pct(s)} of {x['n_members']:,} member sources are known "
                f"research scanners (benignfilter); {_pct(1 - s)} are other "
                f"sources")


def _rdp_cookie(x):
    if x["pattern"] == "rdp_credential_spray" and x.get("rdp_cookie"):
        return (f"RDP mstshash login cookie '{x['rdp_cookie']}' sent by "
                f"{x.get('rdp_cookie_sources') or 0:,} sources")


def _botnet_payload(x):
    if x["botnet_share"] >= BOTNET_SHARE:
        return (f"{_pct(x['botnet_share'])} of {x['n_members']:,} member "
                f"sources sent {x['botnet_family'] or 'botnet'} payloads")


def _http_target(x, want: str) -> str | None:
    t = x["http_template"]
    if not t:
        return None
    for rx, target, verdict, _tech in HTTP_TARGETS:
        if re.search(rx, t):
            return f"'{t}' targets {target}" if verdict == want else None
    return None


def _infra(x):
    # ASN-level findings: the asnintel flag of the ASNs they name, not the
    # correlator's pattern name (its "bp_asn_cluster" groups are 0-5%
    # bulletproof on the 2026-10-29 corpus).
    s = x["asn_bulletproof_share"]
    if x["asn_known"] and s >= BULLETPROOF_SHARE:
        return (f"{_pct(s)} of {x['asn_known']:,} ASNs are flagged bulletproof "
                f"(asnintel); {x['asn_block_grade']:,} graded block_asn")
    # A block-list action needs more than a few sampled members.
    n = x["n_members"]
    enough = n >= MIN_SUPPORT or (n and x["population"] <= n)
    if enough and x["bulletproof_share"] >= BULLETPROOF_SHARE:
        return (f"{_pct(x['bulletproof_share'])} of {n:,} member "
                f"sources are on bulletproof hosting")


def _service_handshake(x):
    svc = x["service"]
    s = x["l7_share"].get(svc, 0.0) if svc else 0.0
    if svc and s >= L7_SHARE:
        cred = ("; the sensor stops before login, so no credential can be "
                "seen" if svc in SERVER_FIRST else
                "; no credential material seen" if svc in AUTH_SERVICES else "")
        return (f"{_pct(s)} of {x['n_members']:,} member sources sent {svc} "
                f"traffic to port {x['port']}{cred}")


def _service_probe(x):
    svc = x["service"]
    share = x["l7_share"].get(svc, 0.0) if svc else 0.0
    if svc and share < L7_SHARE:
        parts = [f"probes of {svc} port {x['port']}"]
        if x["member_syn_only"] >= L7_SHARE:
            parts.append(f"{_pct(x['member_syn_only'])} of member packets are "
                         f"SYN-only")
        if svc in SERVER_FIRST:
            parts.append(f"the sensor sends no {svc} greeting, so no login "
                         f"can be seen")
        elif share:
            parts.append(f"{_pct(share)} of the member sources sent {svc}")
        else:
            parts.append(f"no {svc} L7 events from the member sources")
        return "; ".join(parts)


def _p2p_port(x):
    # No payload protocol of its own, on a port where other findings are
    # P2P by their member facts (a swarm port).
    k = x["port_p2p_findings"]
    other_l7 = max((v for p, v in x["l7_share"].items()
                    if p not in P2P_L7), default=0.0)
    if k and other_l7 < L7_SHARE and x["scanner_share"] < SCANNER_SHARE:
        p2p = sum(x["l7_share"].get(p, 0.0) for p in P2P_L7)
        return (f"port {x['port']} is a P2P swarm port: {k} other findings "
                f"there are P2P by member facts; {_pct(p2p)} of the "
                f"{x['n_members']:,} members sent P2P, and no other protocol "
                f"reached {_pct(L7_SHARE)}")


def _port_scan(x):
    # SYN-only probes of one port that maps to no known service.
    p, syn = x["port"], x["member_syn_only"]
    if p is not None and syn >= L7_SHARE and not x["service"]:
        share = (f"{_pct(x['member_top_port_share'])} of {x['n_members']:,} "
                 f"members have it as top port; " if x["port_from"] == "members"
                 else "")
        return f"probes of port {p}; {share}{_pct(syn)} of member packets are SYN-only"


def _asn_context(x):
    if x["asn_known"] and x["asn_bulletproof_share"] < BULLETPROOF_SHARE:
        return (f"co-hosting cluster of {x['asn_known']:,} ASNs: "
                f"{_pct(x['asn_bulletproof_share'])} bulletproof, "
                f"{x['asn_block_grade']:,} graded block_asn (asnintel)")


def _recon_pattern(x):
    what = RECON_PATTERNS.get(x["pattern"])
    if what:
        return f"correlator pattern: {what}"


def _anomaly_pattern(x):
    what = ANOMALY_PATTERNS.get(x["pattern"])
    if what:
        return f"correlator pattern: {what}"


def _web_l7(x):
    for p in ("http", "tls"):
        s = x["l7_share"].get(p, 0.0)
        if s >= L7_SHARE:
            port = f" (port {x['port']})" if x["port"] else ""
            return f"{_pct(s)} of {x['n_members']:,} member sources sent {p}{port}"


RULES: list[Rule] = [
    Rule("bt_members", "benign_p2p", "", _bt_members),
    Rule("levin_members", "benign_p2p", "", _levin_members),
    Rule("p2p_port", "benign_p2p", "", _p2p_port),
    Rule("bt_surge", "benign_p2p", "", _bt_surge, member_based=False),
    Rule("rdp_cookie", "credential_attack", "T1110.003", _rdp_cookie,
         member_based=False),
    Rule("botnet_payload", "exploit_attempt", "T1190", _botnet_payload),
    # The finding's own request template is its most specific fact, but a
    # sweep that is mostly known scanners stays research_scanner.
    Rule("http_exploit", "exploit_attempt", "T1190",
         lambda x: (_http_target(x, "exploit_attempt")
                    if x["scanner_share"] < SCANNER_SHARE else None),
         member_based=False),
    Rule("http_credentials", "credential_attack", "T1110", _http_credentials),
    Rule("known_scanner", "research_scanner", "T1595", _scanner),
    Rule("http_recon", "service_recon", "T1595.003",
         lambda x: _http_target(x, "service_recon"), member_based=False),
    Rule("hostile_infra", "hostile_infrastructure", "T1583.003", _infra),
    Rule("service_handshake", "service_recon", "T1595.002", _service_handshake),
    Rule("service_probe", "service_recon", "T1595.001", _service_probe),
    Rule("recon_pattern", "service_recon", "T1595", _recon_pattern,
         member_based=False),
    Rule("anomaly_pattern", "protocol_anomaly", "", _anomaly_pattern,
         member_based=False),
    Rule("web_l7", "service_recon", "T1595.003", _web_l7),
    Rule("port_scan", "service_recon", "T1595.001", _port_scan),
    Rule("asn_context", "context", "", _asn_context),
]


def _http_technique(t: str) -> str:
    for rx, _target, _verdict, tech in HTTP_TARGETS:
        if re.search(rx, t):
            return tech
    return "T1595.003"


def _note(facts: dict, verdict_: str) -> str:
    """A hostile subset too small to set the finding's verdict."""
    notes = []
    n = facts["http_auth_sources"]
    if n >= MIN_SUPPORT and verdict_ != "credential_attack":
        notes.append(f"{n:,} non-scanner sources "
                     f"({_pct(n / facts['n_members'])}) sent HTTP credentials")
    b = facts.get("asn_block_grade", 0)
    if b and verdict_ not in ("hostile_infrastructure", "context"):
        notes.append(f"{b:,} of {facts['asn_known']:,} ASNs graded block_asn "
                     f"and {_pct(facts['asn_bulletproof_share'])} flagged "
                     f"bulletproof (asnintel)")
    return "; ".join(notes)


def decide(facts: dict) -> dict:
    """Apply RULES in order.  Pure: same facts -> same verdict."""
    fired = [(r, why) for r in RULES if (why := r.test(facts))]
    if not fired:
        return {"verdict": "unclassified", "rule_id": "", "technique": "",
                "why": "no rule fired", "basis": "none", "also_matched": [],
                "note": _note(facts, "unclassified")}
    rule, why = fired[0]
    tech = rule.technique
    if rule.rule_id in ("http_exploit", "http_recon"):
        tech = _http_technique(facts["http_template"])
    n = facts["n_members"]
    if facts["asn_known"] and rule.rule_id in ("hostile_infra", "asn_context") \
            and n == 0:
        basis = "asns"
    elif not rule.member_based or n == 0:
        basis = "pattern"
    elif n >= MIN_SUPPORT and facts["population"] <= n:
        basis = "members"
    else:
        basis = "sample"
    return {"verdict": rule.verdict, "rule_id": rule.rule_id, "technique": tech,
            "why": why, "basis": basis,
            "also_matched": [r.rule_id for r, _ in fired[1:]],
            "note": _note(facts, rule.verdict)}


def target(facts: dict, verdict_: str, rule_id: str) -> str:
    """What a finding is about, for merging findings into problems."""
    if verdict_ == "benign_p2p":
        return ("Monero (Levin) peers" if rule_id == "levin_members"
                else "BitTorrent peers")
    if verdict_ == "context":
        return "ASN co-hosting clusters"
    if verdict_ == "research_scanner":
        return "known research scanners"
    if verdict_ == "hostile_infrastructure":
        return ("bulletproof ASNs" if facts["n_members"] == 0
                else "sources on bulletproof hosting")
    if rule_id == "rdp_cookie":
        return "RDP login (mstshash cookie)"
    if rule_id == "botnet_payload":
        return f"{facts['botnet_family'] or 'botnet'} payloads"
    if rule_id in ("http_exploit", "http_recon", "http_credentials") \
            and facts["http_template"]:
        for rx, name, _v, _t in HTTP_TARGETS:
            if re.search(rx, facts["http_template"]):
                return name
    if rule_id in ("recon_pattern", "anomaly_pattern"):
        return {**RECON_PATTERNS, **ANOMALY_PATTERNS}[facts["pattern"]]
    if rule_id == "web_l7":
        return "web (http / tls)"
    if facts["km_l7"]:
        return f"{facts['km_l7']} on unusual ports"
    if facts["service"]:
        return facts["service"]
    return f"pattern {facts['pattern']}"


def build(con) -> list[dict]:
    findings_path = OUT_DIR / "findings.parquet"
    if not findings_path.exists():
        return []
    findings = pq.read_table(findings_path).to_pylist()
    mfacts = member_facts(con)
    asns = asn_table(con)
    all_facts = {f["finding_id"]: finding_facts(f, mfacts.get(f["finding_id"]), asns)
                 for f in findings}
    # Ports where a finding is P2P by its own members (the bt_members /
    # levin_members test).  A cross-finding fact, set before any rule runs,
    # so decide() stays a pure function of one finding's facts.
    p2p_ports = Counter(x["port"] for x in all_facts.values()
                        if x["port"] is not None
                        and _is_p2p_by_members(x))
    rows = []
    for f in sorted(findings, key=lambda r: r["finding_id"]):
        facts = all_facts[f["finding_id"]]
        facts["port_p2p_findings"] = (
            p2p_ports[facts["port"]] - _is_p2p_by_members(facts)
            if facts["port"] is not None else 0)
        d = decide(facts)
        rows.append({
            "finding_id": f["finding_id"],
            "pattern_id": f["pattern_id"],
            "pattern": facts["pattern"],
            "verdict": d["verdict"],
            "rule_id": d["rule_id"],
            "technique": d["technique"],
            "why": d["why"],
            "action": ACTIONS[d["verdict"]],
            "basis": d["basis"],
            "n_members": facts["n_members"],
            "port": facts["port"],
            "service": facts["service"],
            "also_matched": ",".join(d["also_matched"]),
            "note": d["note"],
            "target": target(facts, d["verdict"], d["rule_id"]),
            "facts": json.dumps(facts, sort_keys=True, separators=(",", ":")),
        })
    return rows


def _day(s: str | None) -> str:
    return (s or "")[:10]


def problems(con, rows: list[dict]) -> list[dict]:
    """Merge findings with the same (verdict, target) into one problem.
    `sources` counts DISTINCT member IPs across the merged findings."""
    findings = {f["finding_id"]: f for f in pq.read_table(
        OUT_DIR / "findings.parquet",
        columns=["finding_id", "first_seen", "last_seen"]).to_pylist()}
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        groups.setdefault((r["verdict"], r["target"]), []).append(r)
    con.register("fp_map", pa.Table.from_pylist(
        [{"finding_id": r["finding_id"], "verdict": v, "target": t}
         for (v, t), rs in groups.items() for r in rs]))
    distinct = {(v, t): n for v, t, n in con.execute("""
        SELECT p.verdict, p.target, count(DISTINCT m.src_ip)
        FROM fp_map p JOIN m USING (finding_id) GROUP BY 1, 2""").fetchall()}
    out = []
    for (v, t), rs in groups.items():
        facts = [json.loads(r["facts"]) for r in rs]
        ports = Counter(f["port"] for f in facts if f["port"] is not None)
        detail = sorted({f["http_template"] for f in facts if f["http_template"]}
                        | {f["botnet_family"] for f in facts
                           if f["botnet_family"] and v == "exploit_attempt"}
                        | {f"{f['asn_known']:,} ASNs, {_pct(f['asn_bulletproof_share'])} "
                           f"bulletproof, {f['asn_block_grade']:,} block_asn"
                           for f in facts
                           if f["asn_known"] and v == "hostile_infrastructure"})
        seen = [findings.get(r["finding_id"], {}) for r in rs]
        firsts = [_day(x.get("first_seen")) for x in seen if _day(x.get("first_seen"))]
        lasts = [_day(x.get("last_seen")) for x in seen if _day(x.get("last_seen"))]
        cred = 0 if v == "credential_attack" else sum(
            f["http_auth_sources"] for f in facts
            if f["http_auth_sources"] >= MIN_SUPPORT)
        block = 0 if v in ("hostile_infrastructure", "context") else sum(
            f["asn_block_grade"] for f in facts)
        note = "; ".join(x for x in (
            f"{cred:,} non-scanner sources sent HTTP credentials" if cred else "",
            f"{block:,} ASNs graded block_asn (asnintel)" if block else "") if x)
        out.append({
            "problem_id": "prob_" + hashlib.sha256(f"{v}|{t}".encode()).hexdigest()[:10],
            "verdict": v, "target": t, "action": ACTIONS[v],
            "finding_count": len(rs),
            "finding_ids": json.dumps(sorted(r["finding_id"] for r in rs)),
            "sources": distinct.get((v, t), 0),
            "population_max": max((f["population"] for f in facts), default=0),
            "ports": ",".join(str(p) for p, _ in sorted(
                ports.items(), key=lambda kv: (-kv[1], kv[0]))[:6]),
            "detail": "; ".join(detail[:6]),
            "rules": ",".join(sorted({r["rule_id"] for r in rs if r["rule_id"]})),
            "techniques": ",".join(sorted({r["technique"] for r in rs
                                           if r["technique"]})),
            "first_seen": min(firsts, default=""),
            "last_seen": max(lasts, default=""),
            "note": note,
        })
    order = {v: i for i, v in enumerate(VERDICT_ORDER)}
    return sorted(out, key=lambda p: (order[p["verdict"]], -p["sources"],
                                      p["target"]))


def sources_text(p: dict) -> str:
    """Distinct member sources; a sampled finding's full population is
    shown when it is larger."""
    n, pop = p["sources"], p["population_max"]
    if n == 0 and pop == 0:
        return "n/a"
    return f"{n:,} (of >= {pop:,})" if pop > n else f"{n:,}"


def problem_table(probs: list[dict]) -> list[str]:
    """Markdown rows of the problem table (shared with the report), then a
    legend with the one action of each verdict present."""
    lines = ["| verdict | target | findings | sources | ports | detail | seen |",
             "| --- | --- | ---: | ---: | --- | --- | --- |"]
    for p in probs:
        seen = (f"{p['first_seen']} to {p['last_seen']}"
                if p["first_seen"] else "")
        detail = "; ".join(x for x in (p["detail"], p["note"]) if x)
        cells = [p["verdict"], p["target"], str(p["finding_count"]),
                 sources_text(p), p["ports"].replace(",", ", "), detail, seen]
        lines.append("| " + " | ".join(c.replace("|", "\\|") for c in cells)
                     + " |")
    present = {p["verdict"] for p in probs}
    lines += ["", "| verdict | action |", "| --- | --- |"]
    lines += [f"| {v} | {ACTIONS[v]} |" for v in VERDICT_ORDER if v in present]
    return lines


def render_md(rows: list[dict], probs: list[dict]) -> str:
    lines = ["# Verdicts (deterministic)", "",
             f"_{len(rows)} findings merged into {len(probs)} problems. Rules: "
             "`src/conclusions/verdict.py`. No LLM._", ""]
    lines += problem_table(probs)
    lines += ["", "| verdict | finding | rule | technique | basis | why | note |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    order = {v: i for i, v in enumerate(VERDICT_ORDER)}
    for r in sorted(rows, key=lambda r: (order[r["verdict"]], r["pattern_id"],
                                         r["finding_id"])):
        why = r["why"].replace("|", "\\|")
        lines.append(f"| {r['verdict']} | `{r['finding_id']}` | {r['rule_id']} "
                     f"| {r['technique']} | {r['basis']} | {why} | {r['note']} |")
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="8GB")
    rows = build(con)
    probs = problems(con, rows) if rows else []
    con.close()
    if not rows:
        print("[verdict] no findings.parquet; run correlate first",
              file=sys.stderr)
        return 0
    pq.write_table(pa.Table.from_pylist(rows, schema=VERDICT_SCHEMA),
                   OUT_DIR / "verdicts.parquet",
                   compression="zstd", compression_level=3)
    pq.write_table(pa.Table.from_pylist(probs, schema=PROBLEM_SCHEMA),
                   OUT_DIR / "problems.parquet",
                   compression="zstd", compression_level=3)
    (OUT_DIR / "verdicts.md").write_text(render_md(rows, probs))
    counts = Counter(r["verdict"] for r in rows)
    print(f"[verdict] {len(rows)} findings: "
          + ", ".join(f"{v}={counts[v]}" for v in VERDICT_ORDER if counts[v])
          + f"; {len(probs)} problems",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())

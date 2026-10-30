#!/usr/bin/env python3
"""
benignfilter — classify known-benign scanner and research traffic.

Identifies IPs belonging to known scanning organizations using three
signals, scored by confidence:

  HIGH   — IP falls in a published CIDR range (Shodan, Censys, etc.)
  HIGH   — HTTP User-Agent matches a known scanner string
  MEDIUM — ASN belongs to a known scanning organization
  LOW    — Behavioral: hits 100+ distinct ports, mostly SYN-only probes

Output
------
  data/reports/benignfilter/benignfilter.parquet
      One row per classified IP with org, confidence, evidence, stats.
  data/reports/benignfilter/benignfilter.md
      Human-readable summary with top scanners, org breakdown, coverage %.

Downstream analyzers LEFT JOIN this table to filter noise.
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from collections import defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

# ------------------------------------------------------------------
# Known scanner CIDR ranges (from OpenFilters/internet-scanners + docs)
# ------------------------------------------------------------------
KNOWN_CIDRS: dict[str, list[str]] = {
    "shodan": [
        "66.240.192.0/18", "71.6.128.0/17", "198.20.64.0/18",
        "209.126.110.0/23",
    ],
    "censys": [
        "162.142.125.0/24", "167.94.138.0/24", "167.94.145.0/24",
        "167.94.146.0/24", "167.248.133.0/24",
    ],
    "shadowserver": [
        "64.62.202.0/24", "74.82.47.0/24", "184.105.139.0/24",
        "184.105.247.0/24", "216.218.206.0/24",
    ],
    "stretchoid": [
        "198.235.24.0/24", "205.210.31.0/24",
    ],
    "rapid7": [
        "5.63.151.0/24", "71.6.233.0/24",
    ],
    "onyphe": [
        "2.16.11.0/24",
        # OpenFilters onyphe.nft (from probe.onyphe.net/ip-ranges.txt)
        "15.204.109.96/31", "15.204.109.103", "15.204.109.224",
        "51.254.49.96/28", "91.196.152.0/24", "91.230.168.0/24",
        "91.231.89.0/24", "94.231.206.0/24", "195.184.76.0/24",
    ],
    # OpenFilters modat.nft (from scanner.modat.io/ipv4.txt)
    "modat": [
        "23.111.14.183", "23.111.14.184/29", "23.111.14.192",
        "31.14.32.4/30", "31.14.32.8", "54.37.81.238",
        "57.129.64.10", "57.129.64.219", "57.129.64.237",
        "85.217.140.0/24", "85.217.149.0/24", "142.91.102.186/31",
        "185.2.80.252/31", "209.58.160.54", "212.73.148.0/24",
    ],
    "internet_measurement": [
        "141.212.121.0/24", "141.212.122.0/24",
        "198.108.66.0/23",
    ],
    "bitsight": [
        "64.41.200.0/24",
    ],
    "alpha_strike": [
        "80.82.77.0/24", "80.82.78.0/24",
    ],
    "kudelski": [
        "185.180.143.0/24",
    ],
    "recyber": [
        "71.6.199.0/24",
    ],
    "quadmetrics": [
        "199.45.154.0/24", "199.45.155.0/24",
    ],
    "intrinsec": [
        "78.153.140.0/24",
    ],
    "net_census": [
        "93.120.27.0/24",
    ],
    "criminalip": [
        "210.16.67.0/24",
    ],
}

_CIDR_RANGES: list[tuple[int, int, str]] = []
for _org, _cidrs in KNOWN_CIDRS.items():
    for _cidr in _cidrs:
        _net = ipaddress.ip_network(_cidr)
        _CIDR_RANGES.append((int(_net.network_address), int(_net.broadcast_address), _org))
_CIDR_RANGES.sort()

# ------------------------------------------------------------------
# Known scanner User-Agent substrings (case-insensitive)
# ------------------------------------------------------------------
UA_PATTERNS: dict[str, list[str]] = {
    "shodan": ["shodan"],
    "censys": ["censys", "censysinspect"],
    "zgrab": ["zgrab"],
    "masscan": ["masscan"],
    "nmap": ["nmap scripting engine"],
    "rapid7": ["sonar.labs", "rapid7"],
    "netcraft": ["netcraft"],
    "onyphe": ["onyphe"],
    "modat": ["modatscanner"],
    "bitsight": ["bitsight"],
    "shadowserver": ["shadowserver"],
    "intrinsec": ["intrinsec"],
    "criminalip": ["criminalip"],
    "zoomeye": ["zoomeye"],
    "fofa": ["fofa"],
    "driftnet": ["driftnet"],
    "expanse": ["expanse", "xpanse", "paloaltonetworks"],
    "greynoise": ["greynoise"],
    "leakix": ["leakix"],
    "stretchoid": ["stretchoid"],
    "internet_census": ["internet census", "internet-census"],
    "internet_measurement": ["university", "research scan", "academic scan"],
}

# ------------------------------------------------------------------
# Known scanner ASNs
# ------------------------------------------------------------------
# The org of each ASN is its GeoLite2-ASN name.  2026-10-28: 398705 is Censys
# (it was "shodan"); 202425 (IP Volume inc, a bulletproof host) and 19994
# (Rackspace Hosting) were removed, they are not scanner orgs; the Alpha Strike
# Labs, second Censys, Driftnet, Internet Measurement Research, Arbor Networks
# (NETSCOUT ATLAS) and Academy for Internet Research ASNs were added.
SCANNER_ASNS: dict[int, str] = {
    398677: "shodan",
    398705: "censys",
    398324: "censys",
    398722: "censys",
    11022: "shadowserver",
    210631: "onyphe",
    213412: "onyphe",
    209334: "modat",
    40027: "bitsight",
    208843: "alpha_strike",
    215778: "alpha_strike",
    42969: "alpha_strike",
    211298: "driftnet",
    399628: "internet_measurement",
    20052: "arbor",
    400161: "academy_for_internet_research",
    21501: "kudelski",
}


def _ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def match_cidr(ip_int: int) -> str | None:
    for lo, hi, org in _CIDR_RANGES:
        if lo <= ip_int <= hi:
            return org
    return None


def match_ua(ua: str) -> str | None:
    ua_lower = ua.lower()
    for org, patterns in UA_PATTERNS.items():
        for pat in patterns:
            if pat in ua_lower:
                return org
    return None


RESULT_SCHEMA = pa.schema([
    ("src_ip",       pa.string()),
    ("org",          pa.string()),
    ("confidence",   pa.string()),
    ("evidence",     pa.string()),
    ("pkt_count",    pa.uint64()),
    ("port_count",   pa.uint32()),
    ("proto_tcp",    pa.uint64()),
    ("proto_udp",    pa.uint64()),
    ("proto_icmp",   pa.uint64()),
    ("syn_only_pct", pa.float32()),
    ("first_seen",   pa.timestamp("us", tz="UTC")),
    ("last_seen",    pa.timestamp("us", tz="UTC")),
    ("day_count",    pa.uint16()),
    ("country_iso",  pa.string()),
    ("asn",          pa.uint32()),
    ("asn_org",      pa.string()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[benignfilter] aggregating per-IP stats from packets...", file=sys.stderr)
    ip_rows = con.execute(f"""
        SELECT
            src_ip,
            count(*)                              AS pkt_count,
            count(DISTINCT dst_port)              AS port_count,
            count(*) FILTER (WHERE proto = 6)     AS proto_tcp,
            count(*) FILTER (WHERE proto = 17)    AS proto_udp,
            count(*) FILTER (WHERE proto = 1)     AS proto_icmp,
            count(*) FILTER (WHERE tcp_flags = 2) AS syn_only,
            min(ts)                               AS first_seen,
            max(ts)                               AS last_seen,
            count(DISTINCT dt)                    AS day_count
        FROM packets
        WHERE {where}
        GROUP BY src_ip
    """).fetchall()
    total_pkts = sum(r[1] for r in ip_rows)
    print(f"[benignfilter] {len(ip_rows):,} unique source IPs", file=sys.stderr)

    print("[benignfilter] loading user-agent IOCs...", file=sys.stderr)
    ua_map: dict[str, list[str]] = defaultdict(list)
    ua_rows = con.execute(f"""
        SELECT src_ip, value
        FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['user_agent']} AND {where}
        GROUP BY src_ip, value
    """).fetchall()
    for ip, ua in ua_rows:
        ua_map[ip].append(ua)
    print(f"[benignfilter] {len(ua_map):,} IPs with user-agents", file=sys.stderr)

    # columns: src_ip(0) pkt_count(1) port_count(2) proto_tcp(3) proto_udp(4)
    #          proto_icmp(5) syn_only(6) first_seen(7) last_seen(8) day_count(9)

    print("[benignfilter] classifying IPs...", file=sys.stderr)
    geo = lib.GeoLookup()
    results: list[dict] = []
    org_counts: dict[str, int] = defaultdict(int)
    total_benign_pkts = 0

    for row in ip_rows:
        ip = row[0]
        pkt_count = row[1]
        port_count = row[2]
        proto_tcp = row[3]
        proto_udp = row[4]
        proto_icmp = row[5]
        syn_only = row[6]
        first_seen = row[7]
        last_seen = row[8]
        day_count = row[9]

        if not lib.is_real_external_ip(ip):
            continue

        org = None
        confidence = None
        evidence_parts: list[str] = []

        try:
            ip_int = _ip_to_int(ip)
            cidr_org = match_cidr(ip_int)
            if cidr_org:
                org = cidr_org
                confidence = "high"
                evidence_parts.append(f"cidr:{cidr_org}")
        except (ValueError, IndexError):
            pass

        uas = ua_map.get(ip, [])
        for ua in uas:
            ua_org = match_ua(ua)
            if ua_org:
                if org is None:
                    org = ua_org
                confidence = "high"
                evidence_parts.append(f"ua:{ua[:80]}")
                break

        geo_rec = geo.lookup(ip)
        if geo_rec.asn and geo_rec.asn in SCANNER_ASNS:
            asn_org = SCANNER_ASNS[geo_rec.asn]
            if org is None:
                org = asn_org
            if confidence is None:
                confidence = "medium"
            evidence_parts.append(f"asn:{geo_rec.asn}:{asn_org}")

        syn_pct = syn_only / pkt_count if pkt_count > 0 else 0
        if org is None and port_count >= 100 and syn_pct >= 0.8:
            org = "mass_scanner"
            confidence = "low"
            evidence_parts.append(f"behavioral:ports={port_count},syn={syn_pct:.0%}")

        if org is None:
            continue

        org_counts[org] += 1
        total_benign_pkts += int(pkt_count)
        results.append({
            "src_ip":       ip,
            "org":          org,
            "confidence":   confidence,
            "evidence":     "; ".join(evidence_parts),
            "pkt_count":    int(pkt_count),
            "port_count":   int(port_count),
            "proto_tcp":    int(proto_tcp),
            "proto_udp":    int(proto_udp),
            "proto_icmp":   int(proto_icmp),
            "syn_only_pct": float(syn_pct),
            "first_seen":   first_seen,
            "last_seen":    last_seen,
            "day_count":    int(day_count),
            "country_iso":  geo_rec.country_iso,
            "asn":          geo_rec.asn,
            "asn_org":      geo_rec.asn_org,
        })

    geo.close()
    con.close()

    results.sort(key=lambda r: r["pkt_count"], reverse=True)
    total_ips = len(ip_rows)
    benign_ips = len(results)

    org_summary = sorted(org_counts.items(), key=lambda x: x[1], reverse=True)
    by_conf = defaultdict(int)
    for r in results:
        by_conf[r["confidence"]] += 1

    md = f"""## Coverage

- **{benign_ips:,}** IPs classified as known-benign out of **{total_ips:,}** total ({benign_ips / total_ips * 100:.1f}%)
- **{total_benign_pkts:,}** packets from benign scanners ({total_benign_pkts / total_pkts * 100:.1f}% of all traffic)

## Confidence breakdown

| Confidence | IPs |
| --- | --- |
"""
    for conf in ("high", "medium", "low"):
        md += f"| {conf} | {by_conf.get(conf, 0):,} |\n"

    md += "\n## By organization\n\n"
    md += lib.markdown_table(
        [{"org": o, "ips": c} for o, c in org_summary],
        columns=["org", "ips"],
    )

    top_n = args.limit or 30
    md += f"\n## Top {top_n} benign scanners by packet volume\n\n"
    md += lib.markdown_table(
        [{k: v for k, v in r.items()
          if k in ("src_ip", "org", "confidence", "pkt_count", "port_count", "day_count", "asn_org")}
         for r in results[:top_n]],
        columns=["src_ip", "org", "confidence", "pkt_count", "port_count", "day_count", "asn_org"],
    )

    print(f"[benignfilter] classified {benign_ips:,} benign IPs "
          f"({total_benign_pkts:,} packets, {total_benign_pkts / total_pkts * 100:.1f}% of traffic)",
          file=sys.stderr)

    return lib.Report(name="benignfilter", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[benignfilter] wrote {paths['parquet']}")
    print(f"[benignfilter] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

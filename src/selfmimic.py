#!/usr/bin/env python3
"""
selfmimic - detect attackers mimicking the sensor's own banners and
infrastructure responses.

Honeypots that respond with realistic banners eventually leak telltale
strings; sophisticated attackers re-use those exact strings in their own
ClientHello/User-Agent/HTTP headers to look "internal" or to fingerprint
us back.  This module scans inbound traffic for echo of our own
fingerprint.

Inputs:
  - SELF_BANNERS: hard-coded list of sensor fingerprint strings.  Edit
    the constant or override via --banner-file (one per line).
  - iocs.value text (user_agent / http_uri / tls_sni / ssh_banner /
    http_host) - searched for exact and substring matches.

Outputs:
  - selfmimic.parquet: per-source-IP echo count, which banners they
    echoed, and a "mimic_score" 0..1
  - selfmimic.md: human summary
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


RESULT_SCHEMA = pa.schema([
    ("src_ip",       pa.string()),
    ("echo_count",   pa.uint32()),
    ("banner_hits",  pa.string()),
    ("mimic_score",  pa.float32()),
    ("first_seen",   pa.timestamp("us", tz="UTC")),
    ("last_seen",    pa.timestamp("us", tz="UTC")),
    ("country_iso",  pa.string()),
    ("asn",          pa.uint32()),
    ("asn_org",      pa.string()),
])

# Default sensor self-banners.  These are intentionally generic - update
# this list to match the actual honeypot you're running.  The matcher
# does both exact and substring checks.
SELF_BANNERS = [
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-OpenSSH_8.0",
    "Microsoft-IIS/10.0",
    "Apache/2.4.41",
    "nginx/1.18.0",
    "Server: nginx",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0",
    "honeypot",
    "sensorgrind",
]

# Restrict to text-bearing IOC kinds.
TEXT_IOC_KINDS = ["user_agent", "ssh_banner", "http_uri", "tls_sni",
                  "http_host", "dns_query"]


def _load_banners(arg_file: str | None) -> list[str]:
    if not arg_file:
        return SELF_BANNERS
    path = Path(arg_file)
    if not path.exists():
        print(f"[selfmimic] banner file not found: {path}", file=sys.stderr)
        return SELF_BANNERS
    out: list[str] = []
    for ln in path.read_text().splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out or SELF_BANNERS


def run(args: argparse.Namespace) -> lib.Report:
    banners = _load_banners(args.banner_file)
    print(f"[selfmimic] searching for {len(banners)} self-banners",
          file=sys.stderr)

    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))
    kind_ids = [lib.IOC_ID[k] for k in TEXT_IOC_KINDS if k in lib.IOC_ID]
    kind_list = ",".join(str(k) for k in kind_ids)

    # Build a single OR-of-LIKE predicate against the iocs.value column.
    # Substring match catches partial echoes (e.g. attacker appended path).
    like_clauses = []
    for b in banners:
        safe = b.replace("'", "''")
        like_clauses.append(f"value LIKE '%{safe}%'")
    pred = " OR ".join(like_clauses) or "FALSE"

    print("[selfmimic] scanning iocs for banner echoes...", file=sys.stderr)
    rows = con.execute(f"""
        SELECT src_ip, value, ioc_kind, count(*) AS hits,
               min(ts) AS first_seen, max(ts) AS last_seen
        FROM iocs
        WHERE ioc_kind IN ({kind_list})
              AND ({pred})
              AND {where}
        GROUP BY src_ip, value, ioc_kind
    """).fetchall()
    con.close()
    print(f"[selfmimic] {len(rows):,} echo events", file=sys.stderr)

    per_ip: dict[str, dict] = defaultdict(lambda: {
        "echo_count": 0,
        "banners": set(),
        "first_seen": None,
        "last_seen": None,
    })
    for ip, val, kind, hits, fs, ls in rows:
        if not lib.is_real_external_ip(ip):
            continue
        d = per_ip[ip]
        d["echo_count"] += int(hits)
        # Find which banner this value echoed (could be multiple).
        for b in banners:
            if b in (val or ""):
                d["banners"].add(b)
        if d["first_seen"] is None or fs < d["first_seen"]:
            d["first_seen"] = fs
        if d["last_seen"] is None or ls > d["last_seen"]:
            d["last_seen"] = ls

    geo = lib.GeoLookup()
    results: list[dict] = []
    max_echo = max((d["echo_count"] for d in per_ip.values()), default=1)
    for ip, d in per_ip.items():
        if d["echo_count"] < args.min_echoes:
            continue
        g = geo.lookup(ip)
        # Score combines echo volume and number of distinct banners
        # echoed.  Cap at 1.0.
        score = min(1.0,
                    0.6 * (d["echo_count"] / max_echo)
                    + 0.4 * (len(d["banners"]) / max(len(banners), 1)))
        results.append({
            "src_ip":      ip,
            "echo_count":  d["echo_count"],
            "banner_hits": "; ".join(sorted(d["banners"])[:5]),
            "mimic_score": float(score),
            "first_seen":  d["first_seen"],
            "last_seen":   d["last_seen"],
            "country_iso": g.country_iso,
            "asn":         g.asn,
            "asn_org":     g.asn_org,
        })
    geo.close()
    results.sort(key=lambda r: r["mimic_score"], reverse=True)

    md = (
        "## Summary\n\n"
        f"- **{len(results):,}** source IPs echoed sensor self-banners "
        f"(>= {args.min_echoes} hits).\n"
        f"- Banner set: {len(banners)} strings.\n\n"
        "_The presence of our own banner strings in inbound traffic is "
        "an indicator of active sensor fingerprinting or "
        "honeypot-aware tooling.  Pivot to the source IP's other "
        "behavior (timing, payloads, port set) before deciding intent — "
        "low-volume echoes can also be search-engine crawlers or "
        "internet-wide scanners reflecting back a copied banner._\n\n"
        "## Top 30 mimicking IPs\n\n"
    )
    md += lib.markdown_table(
        results[:30],
        columns=["src_ip", "echo_count", "mimic_score", "banner_hits",
                 "country_iso", "asn_org"],
    )

    print(f"[selfmimic] {len(results):,} mimicking IPs", file=sys.stderr)
    return lib.Report(name="selfmimic", rows=results,
                      schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    ap.add_argument("--banner-file", default=None,
                    help="Optional file with one self-banner per line. "
                         "Overrides the built-in SELF_BANNERS list.")
    ap.add_argument("--min-echoes", type=int, default=2,
                    help="Suppress IPs with fewer than N echo events "
                         "(default 2 - single hits are usually noise).")
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[selfmimic] wrote {paths['parquet']}")
    print(f"[selfmimic] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

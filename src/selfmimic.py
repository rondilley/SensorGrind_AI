#!/usr/bin/env python3
"""
selfmimic - detect attackers mimicking the sensor's own banners and
infrastructure responses.

Honeypots that respond with realistic banners eventually leak telltale
strings; sophisticated attackers re-use those exact strings in their
own ClientHello / User-Agent / HTTP headers to look "internal" or to
fingerprint us back.  This module scans inbound traffic for echoes of
our own fingerprint.

**Per-sensor configuration required.**  The matcher is only meaningful
when ``SELF_BANNERS`` actually contains the strings *this specific
honeypot* emits.  For an ultra-low-interaction sensor that never
speaks at layer 7 (like Tom Liston's stateless-TCP design used by
``honeypi00`` in this project), no L7 banner is ever emitted, so the
correct value is the empty list and the analyzer becomes a no-op.
A previous default contained generic banners ("nginx/1.18.0",
"Microsoft-IIS/10.0", a common Chrome User-Agent string, etc.) which
produced false positives on any ultra-low-interaction setup: the
analyzer would flag any inbound packet containing those generic
strings (e.g. a routine scanner using the Chrome UA) as "echoing the
sensor's banners," and the downstream LLM-narrated finding would
hallucinate a counter-honeypot adversary.  See `BLOG_POST.md` for the
case study.

If you run a high-interaction honeypot, override ``SELF_BANNERS``
below (or pass ``--banner-file``) with the *actual* banner strings
your emulator emits.

Inputs:
  - ``SELF_BANNERS``: per-sensor list of fingerprint strings the
    honeypot actually emits.  Default is empty (no-op) - safe for
    ultra-low-interaction sensors.  Override via ``--banner-file``
    (one per line) for high-interaction honeypots.
  - ``iocs.value`` text (user_agent / http_uri / tls_sni / ssh_banner /
    http_host / dns_query) - searched for exact and substring matches.

Outputs:
  - ``selfmimic.parquet``: per-source-IP echo count, which banners
    they echoed, and a "mimic_score" 0..1.  Empty when ``SELF_BANNERS``
    is empty.
  - ``selfmimic.md``: human summary.
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

# Default sensor self-banners.  Empty by default — the analyzer only
# produces a meaningful signal when this list (or --banner-file) is
# populated with banner strings the specific honeypot actually emits.
# For ultra-low-interaction sensors that never speak at L7 (the
# `honeypi00` host shipped with this project, stateless-TCP design),
# the empty list is correct and turns the analyzer into a no-op rather
# than producing false-positive "the sensor's banner appeared in
# inbound traffic" findings against generic scanner UAs.
#
# For high-interaction honeypots (Cowrie, Dionaea, T-Pot etc.) replace
# this with the exact strings your emulator emits — version banners,
# server headers, default SSH/TLS fingerprints, etc.  Use --banner-file
# to avoid editing this source.
SELF_BANNERS: list[str] = []

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
    if not banners:
        # No banners configured = ultra-low-interaction sensor (or
        # operator hasn't populated SELF_BANNERS yet).  Either way,
        # nothing to match against; write an empty result rather than
        # scanning iocs for substring hits against a generic banner
        # list that would produce false positives.
        print("[selfmimic] SELF_BANNERS is empty - skipping "
              "(populate the list with banners THIS sensor actually "
              "emits, or pass --banner-file).  No-op is the correct "
              "behaviour for ultra-low-interaction honeypots.",
              file=sys.stderr)
        md = (
            "## Summary\n\n"
            "_No self-banners configured.  This analyzer requires "
            "`SELF_BANNERS` (or `--banner-file`) to be populated with "
            "the exact strings the sensor emits at layer 7.  "
            "Ultra-low-interaction honeypots that never speak at L7 "
            "(stateless TCP / SYN-only responders) correctly produce "
            "no output here._\n"
        )
        return lib.Report(name="selfmimic", rows=[],
                          schema=RESULT_SCHEMA, markdown=md)

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

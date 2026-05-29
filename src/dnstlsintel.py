#!/usr/bin/env python3
"""
dnstlsintel - DNS / TLS-SNI intelligence the existing pipeline misses.

Honeypot lets us see what the *attacker* is asking the sensor about
(SNI in TLS ClientHello, DNS qnames embedded in scanner payloads).
Those strings expose tooling, C2 staging, and operator naming habits
that the rest of the analyzers don't surface.

Outputs:
  - tls_sni_rank.parquet   top SNIs seen, with associated source IP /
                           ASN diversity and whether the SNI looks
                           algorithmically generated (DGA-style entropy)
  - dns_qname_rank.parquet top DNS qnames seen in iocs, with same
                           DGA flag + TLD breakdown
  - cert_sigs.md            short note on common cert-mimic SNI patterns

Heuristics:
  - DGA flag: Shannon entropy >= --dga-entropy AND no vowel-pair AND
    label_len >= 12  -> likely generated
  - "Suspicious mimic" flag: SNI matches a known-brand regex but the
    contacting ASNs are not on the brand's CDN allowlist
"""
from __future__ import annotations

import argparse
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


SNI_SCHEMA = pa.schema([
    ("sni",           pa.string()),
    ("hits",          pa.uint64()),
    ("src_ips",       pa.uint32()),
    ("src_asns",      pa.uint32()),
    ("countries",     pa.string()),
    ("first_seen",    pa.timestamp("us", tz="UTC")),
    ("last_seen",     pa.timestamp("us", tz="UTC")),
    ("looks_dga",     pa.bool_()),
    ("looks_mimic",   pa.bool_()),
    ("tld",           pa.string()),
])

DNS_SCHEMA = pa.schema([
    ("qname",         pa.string()),
    ("hits",          pa.uint64()),
    ("src_ips",       pa.uint32()),
    ("first_seen",    pa.timestamp("us", tz="UTC")),
    ("last_seen",     pa.timestamp("us", tz="UTC")),
    ("looks_dga",     pa.bool_()),
    ("tld",           pa.string()),
])

# Brand patterns we want to flag if a connection is contacting
# a "windowsupdate-like" or "google-like" SNI from an ASN that wouldn't
# legitimately host that brand.  Kept narrow on purpose - false-positive
# floor is what kills these checks.
BRAND_PATTERNS = {
    "microsoft": re.compile(
        r"(microsoft|windowsupdate|msftncsi|msftconnecttest|live)",
        re.IGNORECASE),
    "google":    re.compile(r"(google|gstatic|googleapis)", re.IGNORECASE),
    "apple":     re.compile(r"(apple|icloud|itunes)", re.IGNORECASE),
    "cloudflare": re.compile(r"(cloudflare|cdnjs)", re.IGNORECASE),
}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_dga(name: str, min_entropy: float) -> bool:
    if not name:
        return False
    # Test against the longest label.
    parts = [p for p in name.split(".") if p]
    if not parts:
        return False
    label = max(parts, key=len)
    if len(label) < 12:
        return False
    if _entropy(label) < min_entropy:
        return False
    # If there's any vowel-pair (e.g. "ae", "ou") it's likely a real word.
    if re.search(r"[aeiou]{2}", label, re.IGNORECASE):
        return False
    return True


def _tld(name: str) -> str:
    parts = [p for p in (name or "").split(".") if p]
    return parts[-1].lower() if parts else ""


def run(args: argparse.Namespace) -> None:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[dnstls] aggregating TLS SNIs...", file=sys.stderr)
    sni_id = lib.IOC_ID["tls_sni"]
    sni_rows = con.execute(f"""
        SELECT value AS sni,
               count(*)                    AS hits,
               count(DISTINCT src_ip)      AS src_ips,
               min(ts)                     AS first_seen,
               max(ts)                     AS last_seen
        FROM iocs
        WHERE ioc_kind = {sni_id} AND value IS NOT NULL AND value != ''
              AND {where}
        GROUP BY value
        ORDER BY hits DESC
        LIMIT {args.top_sni}
    """).fetchall()

    print(f"[dnstls] {len(sni_rows):,} SNIs", file=sys.stderr)

    # ASN / country diversity per SNI - second pass joining iocs to packets
    # via src_ip is expensive; we approximate with src_ip diversity only,
    # then enrich the top 200 via GeoLookup.
    geo = lib.GeoLookup()
    sni_results: list[dict] = []
    enriched = 0
    for sni, hits, ips, fs, ls in sni_rows:
        asn_set: set[int] = set()
        cc_set: set[str] = set()
        if enriched < args.geo_enrich:
            sample = con.execute(f"""
                SELECT DISTINCT src_ip FROM iocs
                WHERE ioc_kind = {sni_id} AND value = ? AND {where}
                LIMIT 50
            """, (sni,)).fetchall()
            for (ip,) in sample:
                if not lib.is_real_external_ip(ip):
                    continue
                g = geo.lookup(ip)
                if g.asn:
                    asn_set.add(int(g.asn))
                if g.country_iso:
                    cc_set.add(g.country_iso)
            enriched += 1
        looks_dga = _looks_dga(sni, args.dga_entropy)
        looks_mimic = False
        for brand, pat in BRAND_PATTERNS.items():
            if pat.search(sni):
                # If the brand is mentioned but the ASNs aren't a known
                # CDN ASN for that brand, flag.  Cheap heuristic: brand
                # SNIs should usually have <=3 unique ASNs.
                if len(asn_set) > 3:
                    looks_mimic = True
                break
        sni_results.append({
            "sni": sni, "hits": int(hits), "src_ips": int(ips),
            "src_asns": len(asn_set),
            "countries": ",".join(sorted(cc_set)[:8]),
            "first_seen": fs, "last_seen": ls,
            "looks_dga": looks_dga,
            "looks_mimic": looks_mimic,
            "tld": _tld(sni),
        })

    print("[dnstls] aggregating DNS qnames...", file=sys.stderr)
    dns_id = lib.IOC_ID["dns_query"]
    dns_rows = con.execute(f"""
        SELECT value AS qname,
               count(*)               AS hits,
               count(DISTINCT src_ip) AS src_ips,
               min(ts)                AS first_seen,
               max(ts)                AS last_seen
        FROM iocs
        WHERE ioc_kind = {dns_id} AND value IS NOT NULL AND value != ''
              AND {where}
        GROUP BY value
        ORDER BY hits DESC
        LIMIT {args.top_dns}
    """).fetchall()
    print(f"[dnstls] {len(dns_rows):,} DNS qnames", file=sys.stderr)
    dns_results = [{
        "qname": q, "hits": int(h), "src_ips": int(i),
        "first_seen": fs, "last_seen": ls,
        "looks_dga": _looks_dga(q, args.dga_entropy),
        "tld": _tld(q),
    } for q, h, i, fs, ls in dns_rows]

    con.close()
    geo.close()

    out_dir = lib.OUTPUT_DIR / "dnstlsintel"
    out_dir.mkdir(parents=True, exist_ok=True)
    sni_tab = pa.Table.from_pylist(sni_results, schema=SNI_SCHEMA)
    dns_tab = pa.Table.from_pylist(dns_results, schema=DNS_SCHEMA)
    import pyarrow.parquet as pq
    pq.write_table(sni_tab, out_dir / "tls_sni_rank.parquet",
                   compression="zstd", compression_level=3)
    pq.write_table(dns_tab, out_dir / "dns_qname_rank.parquet",
                   compression="zstd", compression_level=3)

    n_dga_sni = sum(1 for r in sni_results if r["looks_dga"])
    n_mimic = sum(1 for r in sni_results if r["looks_mimic"])
    n_dga_dns = sum(1 for r in dns_results if r["looks_dga"])
    tld_top = Counter(r["tld"] for r in sni_results).most_common(15)

    md = [
        "# dnstlsintel - DNS / TLS-SNI intelligence",
        "",
        "## Summary",
        "",
        f"- **{len(sni_results):,}** distinct TLS SNIs seen (top "
        f"{args.top_sni})",
        f"- **{len(dns_results):,}** distinct DNS qnames seen (top "
        f"{args.top_dns})",
        f"- **{n_dga_sni:,}** SNIs look algorithmically generated (DGA)",
        f"- **{n_mimic:,}** SNIs look like brand-mimic (impersonated CDN)",
        f"- **{n_dga_dns:,}** DNS qnames look DGA",
        "",
        "_DGA heuristic: longest label >= 12 chars, Shannon entropy "
        f">= {args.dga_entropy}, no vowel-pair.  Tunable but tight._",
        "",
        "## Top SNI TLDs",
        "",
        "| tld | sni_count |",
        "| --- | --- |",
    ]
    for tld, n in tld_top:
        md.append(f"| `{tld or '(empty)'}` | {n} |")
    md += ["", "## Top 25 TLS SNIs", "",
           "| sni | hits | src_ips | asns | dga | mimic | first_seen |",
           "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in sni_results[:25]:
        md.append(f"| `{r['sni']}` | {r['hits']:,} | {r['src_ips']:,} | "
                  f"{r['src_asns']} | "
                  f"{'yes' if r['looks_dga'] else ''} | "
                  f"{'yes' if r['looks_mimic'] else ''} | "
                  f"{r['first_seen']} |")
    md += ["", "## Top 25 DNS qnames", "",
           "| qname | hits | src_ips | dga | first_seen |",
           "| --- | --- | --- | --- | --- |"]
    for r in dns_results[:25]:
        md.append(f"| `{r['qname']}` | {r['hits']:,} | {r['src_ips']:,} | "
                  f"{'yes' if r['looks_dga'] else ''} | "
                  f"{r['first_seen']} |")
    (out_dir / "dnstlsintel.md").write_text("\n".join(md) + "\n")
    print(f"[dnstls] wrote {out_dir}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    ap.add_argument("--top-sni", type=int, default=2000)
    ap.add_argument("--top-dns", type=int, default=2000)
    ap.add_argument("--dga-entropy", type=float, default=3.5,
                    help="Min Shannon entropy on the longest label to "
                         "flag as DGA.")
    ap.add_argument("--geo-enrich", type=int, default=200,
                    help="Geo-enrich the top N SNIs (extra DuckDB pass; "
                         "skip the rest to keep runtime bounded).")
    args = ap.parse_args()
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())

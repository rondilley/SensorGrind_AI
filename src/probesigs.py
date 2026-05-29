#!/usr/bin/env python3
"""
probesigs — CVE/exploit probe tagging from HTTP URIs and payload strings.

Matches HTTP URIs and payload strings against known exploit probe
signatures (derived from Nuclei templates and ET Open rules). Tags
each match with a CVE ID or exploit name, and tracks prevalence
over time.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

# URI patterns → CVE/exploit tags (ordered by specificity)
PROBE_SIGS: list[tuple[str, str, str]] = [
    # (regex_pattern, cve_or_name, description)
    (r"/\.env", "ENV_DISCLOSURE", "dotenv file probe"),
    (r"/wp-login\.php", "WP_LOGIN", "WordPress login brute-force"),
    (r"/wp-admin", "WP_ADMIN", "WordPress admin probe"),
    (r"/xmlrpc\.php", "WP_XMLRPC", "WordPress XML-RPC abuse"),
    (r"/wp-content/plugins/", "WP_PLUGIN_SCAN", "WordPress plugin enumeration"),
    (r"/actuator", "SPRING_ACTUATOR", "Spring Boot actuator exposure"),
    (r"/\.git/", "GIT_DISCLOSURE", "git repository disclosure"),
    (r"/config\.json", "CONFIG_DISCLOSURE", "config file probe"),
    (r"/api/v\d", "API_ENUM", "API endpoint enumeration"),
    (r"/phpMyAdmin", "PHPMYADMIN", "phpMyAdmin probe"),
    (r"/manager/html", "TOMCAT_MANAGER", "Tomcat manager probe"),
    (r"/solr/", "APACHE_SOLR", "Apache Solr probe"),
    (r"/console", "CONSOLE_PROBE", "debug console probe"),
    (r"/jenkins", "JENKINS", "Jenkins probe"),
    (r"/jmx-console", "JBOSS_JMX", "JBoss JMX console probe"),
    (r"/\.aws/credentials", "AWS_CREDS", "AWS credentials probe"),
    (r"/cgi-bin/", "CGI_PROBE", "CGI-bin probe"),
    (r"/shell\?cd|/exec\?cmd", "RCE_PROBE", "remote code execution probe"),
    (r"\$\{jndi:", "CVE-2021-44228", "Log4Shell (Log4j RCE)"),
    (r"/vendor/phpunit", "CVE-2017-9841", "PHPUnit RCE"),
    (r"/Autodiscover/", "CVE-2021-34473", "Exchange ProxyShell"),
    (r"/ecp/default\.flt", "CVE-2021-26855", "Exchange ProxyLogon"),
    (r"/remote/fgt_lang\?lang=/", "CVE-2018-13379", "FortiGate SSL VPN path traversal"),
    (r"/HNAP1", "HNAP_PROBE", "Home Network Admin Protocol probe"),
    (r"/login\.cgi", "ROUTER_LOGIN", "router/IoT login probe"),
    (r"/setup\.cgi", "ROUTER_SETUP", "router setup page probe"),
    (r"/tmUnblock\.cgi", "LINKSYS_TMUNBLOCK", "Linksys tmUnblock RCE"),
    (r"/goform/", "GOAHEAD_PROBE", "GoAhead web server probe"),
    (r"/boaform/", "BOA_PROBE", "Boa web server probe (IoT)"),
    (r"/GponForm/", "CVE-2018-10561", "GPON router RCE"),
    (r"/sdk/\.\.", "CVE-2021-21972", "VMware vCenter RCE"),
    (r"/owa/auth", "OWA_PROBE", "Outlook Web Access probe"),
    (r"/telescope/requests", "LARAVEL_TELESCOPE", "Laravel Telescope exposure"),
    (r"/debug/default/view", "YII_DEBUG", "Yii debug exposure"),
]

_COMPILED_SIGS = [(re.compile(pat, re.IGNORECASE), cve, desc) for pat, cve, desc in PROBE_SIGS]

RESULT_SCHEMA = pa.schema([
    ("uri",           pa.string()),
    ("probe_tag",     pa.string()),
    ("probe_desc",    pa.string()),
    ("src_ip_count",  pa.uint32()),
    ("hit_count",     pa.uint64()),
    ("first_seen",    pa.timestamp("us", tz="UTC")),
    ("last_seen",     pa.timestamp("us", tz="UTC")),
    ("day_count",     pa.uint16()),
])


def _match_uri(uri: str) -> tuple[str, str] | None:
    for rx, cve, desc in _COMPILED_SIGS:
        if rx.search(uri):
            return cve, desc
    return None


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)
    where = lib.date_predicate("ts", lib.parse_date_arg(args.since),
                               lib.parse_date_arg(args.until))

    print("[probesigs] querying HTTP URIs from iocs...", file=sys.stderr)
    uri_rows = con.execute(f"""
        SELECT value AS uri, count(DISTINCT src_ip) AS src_ip_count,
               count(*) AS hit_count, min(ts) AS first_seen, max(ts) AS last_seen,
               count(DISTINCT dt) AS day_count
        FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['http_uri']} AND {where}
        GROUP BY value ORDER BY src_ip_count DESC
    """).fetchall()
    print(f"[probesigs] {len(uri_rows):,} distinct URIs", file=sys.stderr)

    con.close()

    results: list[dict] = []
    tag_counts: dict[str, int] = defaultdict(int)

    for r in uri_rows:
        uri = r[0]
        match = _match_uri(uri)
        if not match:
            continue
        tag, desc = match
        tag_counts[tag] += 1
        results.append({
            "uri": uri[:512], "probe_tag": tag, "probe_desc": desc,
            "src_ip_count": r[1], "hit_count": r[2],
            "first_seen": r[3], "last_seen": r[4], "day_count": r[5],
        })

    results.sort(key=lambda r: r["src_ip_count"], reverse=True)
    tag_summary = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)
    top_n = args.limit or 40

    md = f"""## Summary

- **{len(uri_rows):,}** distinct HTTP URIs observed
- **{len(results):,}** matched known exploit/probe signatures
- **{len(tag_counts):,}** distinct probe tags

## By probe type

"""
    md += lib.markdown_table(
        [{"tag": t, "uri_count": c} for t, c in tag_summary],
        columns=["tag", "uri_count"])
    md += f"\n## Top {top_n} probe URIs by source IP spread\n\n"
    md += lib.markdown_table(results[:top_n],
        columns=["uri", "probe_tag", "src_ip_count", "hit_count", "day_count"])

    print(f"[probesigs] {len(results):,} probe matches across {len(tag_counts):,} tags",
          file=sys.stderr)
    return lib.Report(name="probesigs", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[probesigs] wrote {paths['parquet']}")
    print(f"[probesigs] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

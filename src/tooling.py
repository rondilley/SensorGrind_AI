#!/usr/bin/env python3
"""
tooling - attacker-tool fingerprinting per source IP.

Goal: answer "what software is this attacker running?".  Maps each
threat IP to the most likely scanner / exploit framework / botnet
client by matching against:

  - JA4 / JA4H / JA4SSH fingerprints (TLS / HTTP / SSH client tells)
  - JA4T (TCP SYN-only) signatures of known tools
  - User-Agent string substrings
  - HTTP URI patterns matching Nuclei templates we tagged via probesigs
  - SSH banner substrings

The rule set below is curated; it's meant as a starting point and a
clear extension point.  Defenders can compare the dominant_tool per
IP against EDR/IDS signatures or threat-intel feeds.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import features as sf
from sg import lib

OUT_DIR = lib.REPORTS / "tooling"
FEATURE_VERSION = 1

# Substring -> tool.  Matching is case-insensitive.
UA_TOOLS = {
    "zgrab":             "zgrab2",
    "masscan":           "masscan",
    "nmap":              "nmap",
    "shodan":            "Shodan worker",
    "censys":            "Censys worker",
    "expanse":           "Palo Alto Xpanse",
    "internetmeasurement": "internet-measurement.com",
    "onyphe":            "ONYPHE",
    "bitsight":          "BitSight",
    "shadowserver":      "ShadowServer",
    "leakix":            "LeakIX",
    "fofa":              "FOFA crawler",
    "zoomeye":           "ZoomEye",
    "criminalip":        "CriminalIP",
    "python-requests":   "python-requests script",
    "go-http-client":    "Go net/http (custom scanner)",
    "libwww-perl":       "libwww-perl",
    "curl":              "curl-based script",
    "wget":              "wget-based script",
    "okhttp":            "OkHttp (mobile/Android)",
    "fasthttp":          "fasthttp (Go scanner)",
    "node-fetch":        "node-fetch script",
    "aiohttp":           "Python aiohttp scanner",
    "scrapy":            "Scrapy crawler",
    "googlebot":         "Googlebot",
    "bingbot":           "Bingbot",
    "yandex":            "YandexBot",
    "phantomjs":         "PhantomJS",
    "headlesschrome":    "Headless Chrome (Puppeteer)",
    "fuzz":              "custom fuzzer (substring match)",
    "burp":              "Burp Suite",
    "nuclei":            "Nuclei",
    "sqlmap":            "sqlmap",
    "nikto":             "Nikto",
    "wpscan":            "WPScan",
    "dirbuster":         "DirBuster",
    "gobuster":          "Gobuster",
    "feroxbuster":       "Feroxbuster",
    "wfuzz":             "Wfuzz",
    "metasploit":        "Metasploit",
    "hydra":             "Hydra (brute-forcer)",
    "ncrack":            "Ncrack",
    "patator":           "Patator",
    "medusa":            "Medusa (brute-forcer)",
}

SSH_BANNER_TOOLS = {
    "openssh":           "OpenSSH client",
    "putty":             "PuTTY",
    "libssh":            "libssh-based scanner",
    "paramiko":          "Python paramiko",
    "go ssh":            "Golang ssh library",
    "russh":             "Rust russh library",
    "asyncssh":          "Python asyncssh",
}

# Probe-tag → tool/framework attribution (probesigs tags carry the matched
# CVE/exploit category; many of these have known signature-source tools).
PROBE_TAG_TOOLS = {
    "CVE-2021-44228":    "Log4Shell scanner (often Nuclei)",
    "CVE-2017-9841":     "PHPUnit RCE scanner",
    "CVE-2021-34473":    "ProxyShell scanner",
    "CVE-2018-10561":    "GPON router exploit kit",
    "CVE-2021-26855":    "ProxyLogon scanner",
    "ENV_DISCLOSURE":    "Laravel / Django credential hunter",
    "GIT_DISCLOSURE":    "git-dumper / repo scanner",
    "WP_LOGIN":          "WordPress brute-force tool",
    "WP_XMLRPC":         "WordPress XMLRPC abuser",
    "PHPMYADMIN":        "phpMyAdmin scanner",
    "TOMCAT_MANAGER":    "Tomcat manager scanner",
    "APACHE_SOLR":       "Solr exploit scanner",
    "HNAP_PROBE":        "HNAP / D-Link router scanner",
    "GOAHEAD_PROBE":     "GoAhead web-server scanner (IoT)",
    "BOA_PROBE":         "Boa web-server scanner (IoT)",
    "GPON_PROBE":        "GPON router exploit",
    "RCE_PROBE":         "generic RCE probe (any framework)",
    "AWS_CREDS":         "AWS-credential hunter",
    "CGI_PROBE":         "CGI-bin scanner (RCE chain)",
    "SPRING_ACTUATOR":   "Spring Boot actuator scanner",
}


RESULT_SCHEMA = pa.schema([
    ("src_ip",         pa.string()),
    ("dominant_tool",  pa.string()),
    ("evidence",       pa.string()),
    ("tool_set",       pa.string()),
])


def _classify_ua(ua: str) -> list[str]:
    if not ua:
        return []
    s = ua.lower()
    out = []
    for substr, name in UA_TOOLS.items():
        if substr in s:
            out.append(name)
    return out


def _classify_banner(b: str) -> list[str]:
    if not b:
        return []
    s = b.lower()
    out = []
    for substr, name in SSH_BANNER_TOOLS.items():
        if substr in s:
            out.append(name)
    return out


def run(args: argparse.Namespace) -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[tooling] no ip features", file=sys.stderr)
        return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    # Per-IP UA samples
    print("[tooling] gathering per-IP user-agents...", file=sys.stderr)
    ua_rows = con.execute(f"""
        SELECT src_ip, value
        FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['user_agent']}
        GROUP BY src_ip, value
    """).fetchall()
    print(f"[tooling]   {len(ua_rows):,} (ip,ua) pairs", file=sys.stderr)

    print("[tooling] gathering per-IP SSH banners...", file=sys.stderr)
    ssh_rows = con.execute(f"""
        SELECT src_ip, value
        FROM iocs
        WHERE ioc_kind = {lib.IOC_ID['ssh_banner']}
        GROUP BY src_ip, value
    """).fetchall()

    print("[tooling] gathering per-IP probe-tags...", file=sys.stderr)
    probes = lib.REPORTS / "probesigs" / "probesigs.parquet"
    probe_rows = []
    if probes.exists():
        probe_rows = con.execute(f"""
            SELECT i.src_ip, p.probe_tag
            FROM iocs i
            JOIN read_parquet('{probes}') p ON i.value = p.uri
            WHERE i.ioc_kind = {lib.IOC_ID['http_uri']}
            GROUP BY i.src_ip, p.probe_tag
        """).fetchall()

    con.close()

    # ---- accumulate evidence per IP ----
    per_ip: dict[str, dict] = defaultdict(lambda: {"tools": Counter(),
                                                    "evidence": []})

    for ip, ua in ua_rows:
        for t in _classify_ua(ua):
            per_ip[ip]["tools"][t] += 1
            per_ip[ip]["evidence"].append(f"ua={ua[:60]}->{t}")

    for ip, banner in ssh_rows:
        for t in _classify_banner(banner):
            per_ip[ip]["tools"][t] += 1
            per_ip[ip]["evidence"].append(f"ssh_banner={banner[:60]}->{t}")

    for ip, tag in probe_rows:
        if tag in PROBE_TAG_TOOLS:
            t = PROBE_TAG_TOOLS[tag]
            per_ip[ip]["tools"][t] += 1
            per_ip[ip]["evidence"].append(f"probe={tag}->{t}")

    # Emit
    out_rows: list[dict] = []
    for ip, d in per_ip.items():
        if not d["tools"]:
            continue
        dominant = d["tools"].most_common(1)[0][0]
        out_rows.append({
            "src_ip": ip,
            "dominant_tool": dominant,
            "evidence": "; ".join(d["evidence"][:8]),
            "tool_set": ", ".join(f"{t}({n})" for t, n in d["tools"].most_common()),
        })
    out_rows.sort(key=lambda r: -len(r["tool_set"]))

    pq.write_table(pa.Table.from_pylist(out_rows, schema=RESULT_SCHEMA),
                   OUT_DIR / "tooling.parquet",
                   compression="zstd", compression_level=3)

    # Tool prevalence summary
    tool_counts = Counter(r["dominant_tool"] for r in out_rows)
    md = [
        "# tooling - attacker-tool fingerprinting per source IP",
        "",
        f"_Classified {len(out_rows):,} IPs to a dominant tool using "
        f"User-Agent, SSH banner, and probesigs probe-tag rule sets._",
        "",
        "## Tool prevalence",
        "",
        "| tool | ips |",
        "| --- | --- |",
    ]
    for t, n in tool_counts.most_common(30):
        md.append(f"| {t} | {n:,} |")

    md.extend(["", "## Top 50 IPs with the richest tool fingerprints", "",
               "| src_ip | dominant_tool | tool_set |",
               "| --- | --- | --- |"])
    for r in out_rows[:50]:
        md.append(f"| {r['src_ip']} | {r['dominant_tool']} | "
                  f"{r['tool_set'][:120]} |")
    (OUT_DIR / "tooling.md").write_text("\n".join(md) + "\n")
    print(f"[tooling] wrote {OUT_DIR} ({len(out_rows)} IPs classified)",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    return run(argparse.Namespace())


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
attackmap — map observed honeypot activity to MITRE ATT&CK techniques.

Uses rule-based mapping from observed behaviors (port scans, credential
stuffing, dropper commands, exploit probes) to ATT&CK technique IDs.
Produces a coverage matrix showing which techniques are observed in
the honeypot data.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

# Behavioral signal → ATT&CK technique mapping
ATTACK_RULES: list[tuple[str, str, str, str]] = [
    # (source_module, condition_field, condition_value_pattern, technique)
    ("portscans",  "scan_type", "horizontal", "T1046 — Network Service Discovery"),
    ("portscans",  "scan_type", "vertical",   "T1046 — Network Service Discovery"),
    ("portscans",  "scan_type", "syn_scan",   "T1046 — Network Service Discovery"),
    ("rdpbrute",   "mstshash",  "*",          "T1110.001 — Brute Force: Password Guessing"),
    ("probesigs",  "probe_tag", "WP_LOGIN",   "T1110.001 — Brute Force: Password Guessing"),
    ("probesigs",  "probe_tag", "CVE-*",      "T1190 — Exploit Public-Facing Application"),
    ("probesigs",  "probe_tag", "RCE_PROBE",  "T1190 — Exploit Public-Facing Application"),
    ("droppers",   "ioc_kind",  "cmd",        "T1059.004 — Command and Scripting: Unix Shell"),
    ("droppers",   "ioc_kind",  "url",        "T1105 — Ingress Tool Transfer"),
    ("botnetcls",  "family",    "mirai*",     "T1583.005 — Acquire Infrastructure: Botnet"),
    ("botnetcls",  "family",    "irc_bot",    "T1071.001 — Application Layer Protocol: Web/IRC"),
    ("probesigs",  "probe_tag", "GIT_DISCLOSURE", "T1213 — Data from Information Repositories"),
    ("probesigs",  "probe_tag", "ENV_DISCLOSURE", "T1552.001 — Unsecured Credentials: Files"),
    ("probesigs",  "probe_tag", "AWS_CREDS",  "T1552.001 — Unsecured Credentials: Files"),
    ("probesigs",  "probe_tag", "TOMCAT_MANAGER", "T1078 — Valid Accounts"),
    ("probesigs",  "probe_tag", "PHPMYADMIN", "T1078 — Valid Accounts"),
    ("tlsintel",   "*",         "no_sni",     "T1573 — Encrypted Channel"),
]

RESULT_SCHEMA = pa.schema([
    ("technique",    pa.string()),
    ("evidence_count", pa.uint32()),
    ("sources",      pa.string()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="8GB")

    print("[attackmap] scanning analyzer outputs for ATT&CK mappings...", file=sys.stderr)
    technique_evidence: dict[str, dict] = defaultdict(lambda: {"count": 0, "sources": set()})

    # Portscans
    path = lib.REPORTS / "portscans" / "portscans.parquet"
    if path.exists() and path.stat().st_size > 0:
        n = con.execute(f"SELECT count(*) FROM read_parquet('{path}')").fetchone()[0]
        if n > 0:
            technique_evidence["T1046 — Network Service Discovery"]["count"] += n
            technique_evidence["T1046 — Network Service Discovery"]["sources"].add("portscans")

    # RDP brute
    path = lib.REPORTS / "rdpbrute" / "rdpbrute.parquet"
    if path.exists() and path.stat().st_size > 0:
        n = con.execute(f"SELECT count(*) FROM read_parquet('{path}')").fetchone()[0]
        if n > 0:
            technique_evidence["T1110.001 — Brute Force: Password Guessing"]["count"] += n
            technique_evidence["T1110.001 — Brute Force: Password Guessing"]["sources"].add("rdpbrute")

    # Probesigs → multiple techniques
    path = lib.REPORTS / "probesigs" / "probesigs.parquet"
    if path.exists() and path.stat().st_size > 0:
        probes = con.execute(f"SELECT probe_tag, count(*) FROM read_parquet('{path}') GROUP BY probe_tag").fetchall()
        for tag, cnt in probes:
            if tag.startswith("CVE-") or tag in ("RCE_PROBE",):
                technique_evidence["T1190 — Exploit Public-Facing Application"]["count"] += cnt
                technique_evidence["T1190 — Exploit Public-Facing Application"]["sources"].add(f"probesigs:{tag}")
            if tag in ("GIT_DISCLOSURE",):
                technique_evidence["T1213 — Data from Information Repositories"]["count"] += cnt
                technique_evidence["T1213 — Data from Information Repositories"]["sources"].add("probesigs")
            if tag in ("ENV_DISCLOSURE", "AWS_CREDS", "CONFIG_DISCLOSURE"):
                technique_evidence["T1552.001 — Unsecured Credentials: Files"]["count"] += cnt
                technique_evidence["T1552.001 — Unsecured Credentials: Files"]["sources"].add("probesigs")
            if tag in ("TOMCAT_MANAGER", "PHPMYADMIN", "WP_LOGIN", "JENKINS"):
                technique_evidence["T1078 — Valid Accounts"]["count"] += cnt
                technique_evidence["T1078 — Valid Accounts"]["sources"].add("probesigs")

    # Droppers
    path = lib.REPORTS / "droppers" / "droppers.parquet"
    if path.exists() and path.stat().st_size > 0:
        dropper_rows = con.execute(f"SELECT ioc_kind, count(*) FROM read_parquet('{path}') GROUP BY ioc_kind").fetchall()
        for kind, cnt in dropper_rows:
            if kind == "cmd":
                technique_evidence["T1059.004 — Command and Scripting: Unix Shell"]["count"] += cnt
                technique_evidence["T1059.004 — Command and Scripting: Unix Shell"]["sources"].add("droppers")
            if kind == "url":
                technique_evidence["T1105 — Ingress Tool Transfer"]["count"] += cnt
                technique_evidence["T1105 — Ingress Tool Transfer"]["sources"].add("droppers")

    # Botnet
    path = lib.REPORTS / "botnetcls" / "botnetcls.parquet"
    if path.exists() and path.stat().st_size > 0:
        n = con.execute(f"SELECT count(*) FROM read_parquet('{path}')").fetchone()[0]
        if n > 0:
            technique_evidence["T1583.005 — Acquire Infrastructure: Botnet"]["count"] += n
            technique_evidence["T1583.005 — Acquire Infrastructure: Botnet"]["sources"].add("botnetcls")

    con.close()

    results = [{
        "technique": tech, "evidence_count": d["count"],
        "sources": ", ".join(sorted(d["sources"])),
    } for tech, d in technique_evidence.items()]
    results.sort(key=lambda r: r["evidence_count"], reverse=True)

    md = f"""## MITRE ATT&CK Coverage

**{len(results):,}** techniques observed in honeypot data.

"""
    md += lib.markdown_table(results, columns=["technique", "evidence_count", "sources"])

    print(f"[attackmap] {len(results):,} ATT&CK techniques mapped", file=sys.stderr)
    return lib.Report(name="attackmap", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[attackmap] wrote {paths['parquet']}")
    print(f"[attackmap] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

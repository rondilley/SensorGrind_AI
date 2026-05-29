#!/usr/bin/env python3
"""
botnetcls — heuristic IoT-botnet family classifier from payload strings.

Classifies Mirai variants, Hajime, Mozi, and other IoT malware families
using signature strings extracted from payload_blobs. Also classifies
generic scanner/exploit tooling (zgrab, masscan, etc.) from payload
patterns.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict

import pyarrow as pa

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from sg import lib

FAMILY_SIGS: list[tuple[str, str, str]] = [
    (r"ECCHI", "mirai", "Mirai ECCHI variant marker"),
    (r"/bin/busybox\s", "mirai", "Mirai busybox command chain"),
    (r"enable\r\nshell\r\nsh\r\n", "mirai", "Mirai telnet enable sequence"),
    (r"cd /tmp", "mirai_dropper", "Mirai dropper stage (cd /tmp)"),
    (r"/dev/null 2>&1", "mirai_dropper", "Mirai shell redirection"),
    (r"HAJIME", "hajime", "Hajime marker"),
    (r"MOZI", "mozi", "Mozi P2P botnet"),
    (r"LZRD", "lzrd", "LZRD botnet variant"),
    (r"SATORI", "satori", "Satori/Okiru variant"),
    (r"TSUNAMI", "tsunami", "Tsunami/Kaiten IRC bot"),
    (r"PRIVMSG", "irc_bot", "IRC bot PRIVMSG command"),
    (r"NICK\s", "irc_bot", "IRC bot NICK registration"),
    (r"GET /shell\?", "rce_scanner", "RCE probe via GET /shell"),
    (r"POST.*cmd=", "rce_scanner", "RCE probe via POST cmd="),
]

_COMPILED_SIGS = [(re.compile(pat, re.IGNORECASE), family, desc)
                  for pat, family, desc in FAMILY_SIGS]

RESULT_SCHEMA = pa.schema([
    ("payload_sha256", pa.binary(32)),
    ("family",         pa.string()),
    ("match_desc",     pa.string()),
    ("payload_len",    pa.uint16()),
    ("l7_proto",       pa.string()),
    ("src_ip_count",   pa.uint32()),
    ("sample_strings", pa.string()),
])


def run(args: argparse.Namespace) -> lib.Report:
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con)

    print("[botnetcls] scanning payload strings for family signatures...", file=sys.stderr)
    rows = con.execute("""
        SELECT payload_sha256, payload_len, l7_proto, strings
        FROM payload_blobs
        WHERE l7_proto IN (7, 13, 1)
    """).fetchall()
    print(f"[botnetcls] {len(rows):,} blobs to classify (telnet/mirai/http)", file=sys.stderr)

    sha_to_family: dict[bytes, tuple[str, str]] = {}
    for r in rows:
        sha, plen, l7, strings = r
        if not strings:
            continue
        joined = " ".join(strings[:32])
        for rx, family, desc in _COMPILED_SIGS:
            if rx.search(joined):
                sha_to_family[sha] = (family, desc)
                break

    print(f"[botnetcls] {len(sha_to_family):,} blobs matched a family", file=sys.stderr)

    # Get IP counts per classified payload
    if sha_to_family:
        sha_list = list(sha_to_family.keys())
        con.execute("CREATE TEMP TABLE classified_sha (sha BLOB)")
        for sha in sha_list:
            con.execute("INSERT INTO classified_sha VALUES (?)", [sha])
        ip_counts = con.execute("""
            SELECT p.payload_sha256, count(DISTINCT p.src_ip) AS src_ip_count
            FROM packets p
            JOIN classified_sha c ON p.payload_sha256 = c.sha
            GROUP BY p.payload_sha256
        """).fetchall()
        ip_map = {r[0]: r[1] for r in ip_counts}
    else:
        ip_map = {}

    con.close()

    results: list[dict] = []
    family_counts: dict[str, int] = defaultdict(int)

    for r in rows:
        sha = r[0]
        if sha not in sha_to_family:
            continue
        family, desc = sha_to_family[sha]
        family_counts[family] += 1
        results.append({
            "payload_sha256": sha, "family": family, "match_desc": desc,
            "payload_len": r[1], "l7_proto": lib.L7_NAME.get(r[2], "unknown"),
            "src_ip_count": ip_map.get(sha, 0),
            "sample_strings": " | ".join((r[3] or [])[:5]),
        })

    results.sort(key=lambda r: r["src_ip_count"], reverse=True)
    fam_summary = sorted(family_counts.items(), key=lambda x: x[1], reverse=True)
    top_n = args.limit or 40

    md = f"""## Summary

- **{len(rows):,}** candidate blobs scanned
- **{len(results):,}** classified into **{len(family_counts):,}** families

## Family breakdown

"""
    md += lib.markdown_table(
        [{"family": f, "blob_count": c} for f, c in fam_summary],
        columns=["family", "blob_count"])
    md += f"\n## Top {top_n} classified payloads by source IP spread\n\n"
    md += lib.markdown_table(results[:top_n],
        columns=["family", "match_desc", "payload_len", "l7_proto", "src_ip_count", "sample_strings"])

    return lib.Report(name="botnetcls", rows=results, schema=RESULT_SCHEMA, markdown=md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    args = ap.parse_args()
    report = run(args)
    paths = report.write()
    print(f"[botnetcls] wrote {paths['parquet']}")
    print(f"[botnetcls] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

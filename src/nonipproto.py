#!/usr/bin/env python3
"""
nonipproto - catalog non-TCP/UDP/ICMP IPv4 traffic the parser silently drops.

The Stage A+B parser only retains lines whose protocol token matches
"IPv4/TCP", "IPv4/UDP", or "IPv4/ICMP". The sensor's actual format for
every other IPv4 protocol is:

    sensor: PacketTime:<date> <time> Len:<n> UNKNOWN-IPv4-Protocol:<NUM>
            <src> -> <dst> ID:<n> TOS:0x<x> TTL:<n> IpLen:<n>
            DgLen:<n> Packetdata:<base64>

These lines never reach the parquet pipeline.  This script scans the
source merged.log.gz, tabulates `UNKNOWN-IPv4-Protocol:<NUM>` by IANA
protocol number, and emits per-protocol counts + a sample payload
prefix so you can spot SCTP (132, telco signaling), GRE (47, tunneling),
6to4 (41, v6-in-v4), IP-in-IP (4), etc.

For each protocol number it captures: packet count, total bytes, TTL
mode, distinct source IPs (bounded), first/last seen dates, and a
hex-printable sample of the first 32 payload bytes.
"""
from __future__ import annotations

import argparse
import base64
import re
import sys
from collections import defaultdict
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib

OUT_DIR = lib.REPORTS / "nonipproto"

# IANA IP protocol numbers, focused on the ones likely to show up at a
# public-facing honeypot.  Generic fallback used for the rest.
PROTO_NUM = {
    1:   ("ICMP",        "Internet Control Message - already captured by main parser"),
    2:   ("IGMP",        "Internet Group Mgmt - multicast control"),
    4:   ("IP-in-IP",    "IP encapsulation - tunnel; can carry anything"),
    6:   ("TCP",         "Transmission Control - already captured"),
    8:   ("EGP",         "Exterior Gateway Protocol - legacy routing"),
    9:   ("IGRP",        "Cisco IGRP - legacy intra-AS routing"),
    17:  ("UDP",         "User Datagram - already captured"),
    27:  ("RDP",         "Reliable Datagram Protocol"),
    33:  ("DCCP",        "Datagram Congestion Control"),
    41:  ("IPv6-in-IPv4", "6to4 tunneling - v6 packets wrapped in v4"),
    43:  ("IPv6-route",  "IPv6 Routing header"),
    46:  ("RSVP",        "Resource Reservation Protocol - QoS"),
    47:  ("GRE",         "Generic Routing Encapsulation - tunneling/VPN"),
    50:  ("ESP",         "IPsec ESP - encrypted tunnel payload"),
    51:  ("AH",          "IPsec AH - authenticated tunnel"),
    58:  ("ICMPv6",      "ICMPv6 inside v4 - unusual"),
    88:  ("EIGRP",       "Cisco EIGRP routing"),
    89:  ("OSPF",        "Open Shortest Path First - intra-AS routing"),
    97:  ("ETHERIP",     "Ether-IP encapsulation"),
    103: ("PIM",         "Protocol Independent Multicast"),
    112: ("VRRP",        "Virtual Router Redundancy"),
    115: ("L2TP",        "Layer 2 Tunneling Protocol - VPN signaling"),
    132: ("SCTP",        "Stream Control Transmission - TELCO signaling (Diameter/SIGTRAN)"),
    136: ("UDPLITE",     "UDP-Lite"),
    137: ("MPLS-in-IP",  "MPLS encapsulation"),
}

RESULT_SCHEMA = pa.schema([
    ("proto_num",     pa.uint8()),
    ("proto_name",    pa.string()),
    ("description",   pa.string()),
    ("packets",       pa.uint64()),
    ("total_bytes",   pa.uint64()),
    ("distinct_srcs", pa.uint32()),
    ("ttl_mode",      pa.uint8()),
    ("first_seen",    pa.string()),
    ("last_seen",     pa.string()),
    ("sample_src",    pa.string()),
    ("sample_hex",    pa.string()),
    ("sample_printable", pa.string()),
])

# Per-(src_ip, proto_num) detail.  The non-TCP/UDP/ICMP corpus is tiny
# (a few thousand lines across the full log), so we persist every src
# that touched a given protocol instead of capping at SRC_CAP.  The
# correlator joins this on src_ip against portscans/scannerintel to find
# IPs that did, say, TCP telco-port scans AND sent SCTP packets.
PER_IP_SCHEMA = pa.schema([
    ("src_ip",     pa.string()),
    ("proto_num",  pa.uint8()),
    ("proto_name", pa.string()),
    ("packets",    pa.uint32()),
    ("total_bytes", pa.uint64()),
    ("first_seen", pa.string()),
    ("last_seen",  pa.string()),
])

PROTO_RE = re.compile(rb" UNKNOWN-IPv4-Protocol:(\d+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) -> ")
LEN_RE   = re.compile(rb" Len:(\d+) ")
TTL_RE   = re.compile(rb" TTL:(\d+) ")
TIME_RE  = re.compile(rb"PacketTime:(\d{4}-\d{2}-\d{2})")
PKTDATA_RE = re.compile(rb" Packetdata:([A-Za-z0-9+/=]+)")

# Parser also handles standard IPv4/TCP|UDP|ICMP - count those for context
KNOWN_PROTO_RE = re.compile(rb" IPv4/(TCP|UDP|ICMP) ")


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(args.input).expanduser()
    if not src.exists():
        print(f"[nonip] input not found: {src}", file=sys.stderr)
        return 2
    print(f"[nonip] scanning {src} for UNKNOWN-IPv4-Protocol lines...",
          file=sys.stderr)

    counts: dict[int, int] = defaultdict(int)
    bytes_seen: dict[int, int] = defaultdict(int)
    srcs: dict[int, set] = defaultdict(set)
    first: dict[int, bytes] = {}
    last: dict[int, bytes] = {}
    sample_src: dict[int, bytes] = {}
    sample_pkt: dict[int, bytes] = {}
    ttl_counts: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    # per-(src_ip,proto) aggregates - unbounded; the corpus is small
    per_ip_pkts:  dict[tuple[bytes, int], int] = defaultdict(int)
    per_ip_bytes: dict[tuple[bytes, int], int] = defaultdict(int)
    per_ip_first: dict[tuple[bytes, int], bytes] = {}
    per_ip_last:  dict[tuple[bytes, int], bytes] = {}

    n_lines = 0
    n_match = 0
    n_known = 0
    SRC_CAP = 50_000  # bound src-set memory per protocol

    import subprocess as sp
    p = sp.Popen(["zcat", str(src)], stdout=sp.PIPE, stderr=sp.DEVNULL,
                 bufsize=1 << 22)
    try:
        for raw in p.stdout:
            n_lines += 1
            mp = PROTO_RE.search(raw)
            if not mp:
                if KNOWN_PROTO_RE.search(raw):
                    n_known += 1
                if args.max_lines and n_lines >= args.max_lines:
                    break
                if n_lines % 50_000_000 == 0:
                    print(f"[nonip]   {n_lines:,} lines scanned, "
                          f"non-TCP/UDP/ICMP matches: {n_match:,}",
                          file=sys.stderr)
                continue
            n_match += 1
            num = int(mp.group(1))
            src_ip = mp.group(2)
            counts[num] += 1
            if len(srcs[num]) < SRC_CAP:
                srcs[num].add(src_ip)
                if num not in sample_src:
                    sample_src[num] = src_ip
            key = (src_ip, num)
            per_ip_pkts[key] += 1
            ml = LEN_RE.search(raw)
            if ml:
                ln = int(ml.group(1))
                bytes_seen[num] += ln
                per_ip_bytes[key] += ln
            mt = TIME_RE.search(raw)
            if mt:
                d = mt.group(1)
                if num not in first or d < first[num]:
                    first[num] = d
                if num not in last or d > last[num]:
                    last[num] = d
                if key not in per_ip_first or d < per_ip_first[key]:
                    per_ip_first[key] = d
                if key not in per_ip_last or d > per_ip_last[key]:
                    per_ip_last[key] = d
            mttl = TTL_RE.search(raw)
            if mttl:
                ttl_counts[num][int(mttl.group(1))] += 1
            mpk = PKTDATA_RE.search(raw)
            if mpk and num not in sample_pkt:
                try:
                    sample_pkt[num] = base64.b64decode(mpk.group(1), validate=False)
                except Exception:
                    pass
            if args.max_lines and n_lines >= args.max_lines:
                break
    finally:
        try:
            p.stdout.close()
        except Exception:
            pass
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()

    print(f"[nonip] {n_lines:,} lines scanned; "
          f"{n_known:,} were standard TCP/UDP/ICMP (parsed); "
          f"{n_match:,} were UNKNOWN-IPv4-Protocol", file=sys.stderr)

    rows: list[dict] = []
    for num, n in sorted(counts.items(), key=lambda x: -x[1]):
        name, desc = PROTO_NUM.get(num, (f"proto-{num}", "Unknown/unmapped IP protocol number"))
        ttl_mode = max(ttl_counts[num], key=ttl_counts[num].get) if ttl_counts[num] else 0
        # Sample payload bytes - skip Ethernet header (14B) + IPv4 header (>=20B).
        # The sensor's Packetdata is the full L2 frame; we want IP payload only.
        raw_bytes = sample_pkt.get(num, b"")
        # IP header starts at byte 14 (Ethernet 14B).  IHL nibble tells header
        # length; payload follows.  Bound-check carefully.
        ip_payload = b""
        if len(raw_bytes) >= 34:
            ihl = (raw_bytes[14] & 0x0F) * 4
            if ihl >= 20 and len(raw_bytes) >= 14 + ihl:
                ip_payload = raw_bytes[14 + ihl: 14 + ihl + 32]
        sample_hex = ip_payload.hex()
        sample_print = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in ip_payload)
        rows.append({
            "proto_num": num,
            "proto_name": name,
            "description": desc,
            "packets": n,
            "total_bytes": bytes_seen[num],
            "distinct_srcs": len(srcs[num]),
            "ttl_mode": ttl_mode,
            "first_seen": first.get(num, b"").decode("ascii", errors="replace"),
            "last_seen":  last.get(num, b"").decode("ascii", errors="replace"),
            "sample_src": sample_src.get(num, b"").decode("ascii", errors="replace"),
            "sample_hex": sample_hex,
            "sample_printable": sample_print,
        })

    pq.write_table(pa.Table.from_pylist(rows, schema=RESULT_SCHEMA),
                   OUT_DIR / "nonipproto.parquet",
                   compression="zstd", compression_level=3)

    # Per-IP detail table - one row per (src_ip, proto_num).
    per_ip_rows = []
    for (sip, num), pkts in sorted(per_ip_pkts.items(), key=lambda x: -x[1]):
        name, _ = PROTO_NUM.get(num, (f"proto-{num}", ""))
        per_ip_rows.append({
            "src_ip":      sip.decode("ascii", errors="replace"),
            "proto_num":   num,
            "proto_name":  name,
            "packets":     pkts,
            "total_bytes": per_ip_bytes.get((sip, num), 0),
            "first_seen":  per_ip_first.get((sip, num), b"").decode("ascii", errors="replace"),
            "last_seen":   per_ip_last.get((sip, num), b"").decode("ascii", errors="replace"),
        })
    pq.write_table(pa.Table.from_pylist(per_ip_rows, schema=PER_IP_SCHEMA),
                   OUT_DIR / "per_ip.parquet",
                   compression="zstd", compression_level=3)
    print(f"[nonip] wrote per_ip detail rows={len(per_ip_rows)}", file=sys.stderr)

    md = [
        "# nonipproto - non-TCP/UDP/ICMP IPv4 traffic catalog", "",
        f"_Scanned {n_lines:,} raw sensor log lines.  "
        f"{n_known:,} were standard IPv4/TCP|UDP|ICMP (already in the "
        f"main parquet store); {n_match:,} were "
        f"`UNKNOWN-IPv4-Protocol:<N>` lines the parser silently drops._",
        "",
        "Each row is one distinct IP protocol number seen at the sensor "
        "but not retained by the parser.  Notable ones to look for: "
        "**132 (SCTP)** = telco signaling (Diameter/SIGTRAN, MAP), "
        "**47 (GRE)** = generic tunneling, "
        "**41 (IPv6-in-IPv4)** = 6to4 / Teredo activity, "
        "**4 (IP-in-IP)** = encapsulation tunnel, "
        "**50/51 (ESP/AH)** = IPsec.  Routing protocols "
        "(89 OSPF, 88 EIGRP, 103 PIM) appearing on a public IP at a "
        "honeypot are highly unusual.",
        "",
        "| proto# | name | description | packets | bytes | distinct_srcs | ttl_mode | first | last | sample_src |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        md.append(f"| {r['proto_num']} | {r['proto_name']} | "
                  f"{r['description']} | {r['packets']:,} | "
                  f"{r['total_bytes']:,} | {r['distinct_srcs']:,} | "
                  f"{r['ttl_mode']} | {r['first_seen']} | "
                  f"{r['last_seen']} | {r['sample_src']} |")

    md.extend(["", "## Sample IP-payload prefixes (first 32 bytes, hex)",
               "",
               "_Hex dump of the IP payload of one sample packet per "
               "protocol, after stripping Ethernet (14B) and IPv4 header.  "
               "Useful for confirming what's actually in the bytes - "
               "e.g. SCTP common header starts with `<src_port:2><dst_port:2>"
               "<verification_tag:4><checksum:4>`._",
               "",
               "| proto | sample_hex | printable |",
               "| --- | --- | --- |"])
    for r in rows:
        md.append(f"| {r['proto_num']} {r['proto_name']} | "
                  f"`{r['sample_hex']}` | `{r['sample_printable']}` |")

    (OUT_DIR / "nonipproto.md").write_text("\n".join(md) + "\n")
    print(f"[nonip] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input",
                    default=str(Path.home() / "git/SensorGrind_AI/data/merged.log.gz"))
    ap.add_argument("--max-lines", type=int, default=0,
                    help="0 = scan all (default). Use small N for smoke tests.")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

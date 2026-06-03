#!/usr/bin/env python3
"""
parser.py — Stage A+B: streaming parser for the honeypot merged log.

Reads ~/git/SensorGrind_AI/data/merged.log.gz, where each line is
``<ISO_UTC>\\t<raw syslog line containing PacketTime: ... Packetdata:<base64>>``.

For every line we:
    1. Parse the text fields (timestamp, src/dst, ports, TCP flags, TTL, ...).
    2. Base64-decode `Packetdata:` -> full L2 Ethernet frame.
    3. Strip Ethernet/IP/TCP|UDP|ICMP headers to isolate the L7 payload.
    4. SHA-256 the payload (dedup key), extract printable strings.
    5. Fingerprint the L7 protocol (HTTP, TLS, SSH, RDP, DNS, BitTorrent, ...).
    6. Mine IOCs from the payload (URLs, IPs, domains, mstshash cookies,
       SSH banners, User-Agents, busybox dropper commands, file hashes).

Outputs four daily-partitioned Parquet datasets under
``data/parquet/<table>/dt=YYYY-MM-DD/part-NNNN.parquet``:

    packets       — one row per input line; flow-level + pointer to payload
    payload_blobs — distinct payload bytes (sha256-deduped)
    l7_events     — per-protocol structured fields (only when a parser fired)
    iocs          — extracted IOCs (one row per IOC observed)

Architecture
------------
Single reader (``zcat`` subprocess) -> multiprocessing.Pool decoder workers
(text+binary parsing, IOC extraction) -> single writer process that buckets
rows by UTC day and rolls a new Parquet file per ``--rows-per-part`` rows.

The merged log is globally sorted by timestamp, so day buckets close cleanly
as we advance through the stream; we never need random access.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import multiprocessing as mp
import os
import re
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pyarrow as pa
import pyarrow.parquet as pq


# ----------------------------------------------------------------------
# Protocol/enum constants
# ----------------------------------------------------------------------

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

# Resp: values seen in this corpus.
RESP_NONE, RESP_SA, RESP_FA, RESP_A, RESP_R, RESP_ICMP = range(6)
RESP_MAP = {
    "": RESP_NONE, "SA": RESP_SA, "FA": RESP_FA, "A": RESP_A,
    "R": RESP_R, "ICMP": RESP_ICMP,
}

# L7 protocol enum.
L7_UNKNOWN, L7_HTTP, L7_TLS, L7_SSH, L7_FTP, L7_SMTP, L7_DNS, \
L7_TELNET, L7_RDP, L7_SMB, L7_MQTT, L7_IRC, L7_BITTORRENT, \
L7_MIRAI, L7_MONGO, L7_REDIS, L7_VNC = range(17)

L7_NAME = {
    L7_UNKNOWN: "unknown", L7_HTTP: "http", L7_TLS: "tls", L7_SSH: "ssh",
    L7_FTP: "ftp", L7_SMTP: "smtp", L7_DNS: "dns", L7_TELNET: "telnet",
    L7_RDP: "rdp", L7_SMB: "smb", L7_MQTT: "mqtt", L7_IRC: "irc",
    L7_BITTORRENT: "bittorrent", L7_MIRAI: "mirai",
    L7_MONGO: "mongo", L7_REDIS: "redis", L7_VNC: "vnc",
}

# IOC kind enum.
IOC_URL, IOC_DOMAIN, IOC_IPV4, IOC_IPV6, IOC_FILE_HASH, IOC_CMD, IOC_CRED, \
IOC_MSTSHASH, IOC_USER_AGENT, IOC_SSH_BANNER, IOC_TLS_SNI, IOC_HTTP_HOST, \
IOC_HTTP_URI, IOC_DNS_QUERY = range(14)

IOC_NAME = {
    IOC_URL: "url", IOC_DOMAIN: "domain", IOC_IPV4: "ipv4", IOC_IPV6: "ipv6",
    IOC_FILE_HASH: "file_hash", IOC_CMD: "cmd", IOC_CRED: "cred",
    IOC_MSTSHASH: "mstshash", IOC_USER_AGENT: "user_agent",
    IOC_SSH_BANNER: "ssh_banner", IOC_TLS_SNI: "tls_sni",
    IOC_HTTP_HOST: "http_host", IOC_HTTP_URI: "http_uri",
    IOC_DNS_QUERY: "dns_query",
}

# TCP flag bit positions (from the U*A*P*R*S*F* mask in the log).
FLAG_URG = 1 << 5
FLAG_ACK = 1 << 4
FLAG_PSH = 1 << 3
FLAG_RST = 1 << 2
FLAG_SYN = 1 << 1
FLAG_FIN = 1 << 0


# ----------------------------------------------------------------------
# Text-line parsing
# ----------------------------------------------------------------------

# We carve up the raw syslog line with anchored field searches rather than
# one giant regex: each field is at a known position, and a few lookups are
# much cheaper than a backtracking match across 400 bytes.

_PACKETTIME_RE = re.compile(rb"PacketTime:(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}\.\d+)")
_PROTO_RE      = re.compile(rb" IPv4/(TCP|UDP|ICMP) ")
_TCP_UDP_FLOW  = re.compile(rb" (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+) -> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+) ")
_ICMP_FLOW     = re.compile(rb" (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) -> (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ")

# Fused field regex.  The original code issued 11+ separate `.search()`
# calls per line - one per `KEY:VALUE` token - which is the dominant CPU
# cost on the 1.1 B-row parse.  A single `finditer` over this combined
# pattern walks each line once and dispatches on `m.lastgroup`.
#   dec_*    decimal-valued keys: Len, ID, TTL, DgLen, TcpLen, Type, Code
#   hex_*    hex-valued keys:     TOS, Seq, Ack, Win
#   resp_v   sensor response code (alphabetic)
#   flags_v  TCP flag mask UAPRSF (`*`-padded for unset bits)
_FIELDS_RE = re.compile(rb"""
    [ ]
    (?:
        (?P<dec_k>Len|ID|TTL|DgLen|TcpLen|Type|Code):(?P<dec_v>\d+)
      | (?P<hex_k>TOS|Seq|Ack|Win):0x(?P<hex_v>[0-9a-fA-F]+)
      | Resp:(?P<resp_v>[A-Z]*)(?=[ \n]|$)
      | (?P<flags_v>[U*][A*][P*][R*][S*][F*])(?=[ \n])
    )
""", re.VERBOSE)
# Cap the base64 capture at ~96 KB encoded => ~64 KB binary, which already
# exceeds the IPv4 total_length max (65 535).  Anything bigger can only be
# either a sensor bug or a malicious / corrupted line trying to exhaust
# worker RAM via `base64.b64decode` at parser.py:610.  Drop the line
# rather than try to decode a multi-megabyte blob.
_PKTDATA_RE    = re.compile(rb" Packetdata:([A-Za-z0-9+/=]{1,131072})")


def _flag_mask_to_int(mask: bytes) -> int:
    """`*A**S*` -> bitmask. mask order is U,A,P,R,S,F."""
    bits = 0
    if mask[0] != 0x2A: bits |= FLAG_URG
    if mask[1] != 0x2A: bits |= FLAG_ACK
    if mask[2] != 0x2A: bits |= FLAG_PSH
    if mask[3] != 0x2A: bits |= FLAG_RST
    if mask[4] != 0x2A: bits |= FLAG_SYN
    if mask[5] != 0x2A: bits |= FLAG_FIN
    return bits


def parse_text_fields(line: bytes) -> dict | None:
    """Carve a single raw log line (bytes) into header fields.

    Returns None if the line doesn't look like a sensor packet.
    """
    m_ts = _PACKETTIME_RE.search(line)
    m_proto = _PROTO_RE.search(line)
    if not m_ts or not m_proto:
        return None

    proto_name = m_proto.group(1)
    if proto_name == b"TCP":
        proto = PROTO_TCP
        flow = _TCP_UDP_FLOW.search(line)
        if not flow:
            return None
        src_ip = flow.group(1).decode("ascii")
        src_port = int(flow.group(2))
        dst_ip = flow.group(3).decode("ascii")
        dst_port = int(flow.group(4))
    elif proto_name == b"UDP":
        proto = PROTO_UDP
        flow = _TCP_UDP_FLOW.search(line)
        if not flow:
            return None
        src_ip = flow.group(1).decode("ascii")
        src_port = int(flow.group(2))
        dst_ip = flow.group(3).decode("ascii")
        dst_port = int(flow.group(4))
    else:  # ICMP
        proto = PROTO_ICMP
        flow = _ICMP_FLOW.search(line)
        if not flow:
            return None
        src_ip = flow.group(1).decode("ascii")
        src_port = None
        dst_ip = flow.group(2).decode("ascii")
        dst_port = None

    # Single-pass scan of the line's KEY:VALUE tokens.  Each match
    # dispatches by `lastgroup` into one of three buckets.
    dec_fields: dict[bytes, int] = {}
    hex_fields: dict[bytes, int] = {}
    tcp_flags_raw: bytes | None = None
    sensor_resp = RESP_NONE
    for m in _FIELDS_RE.finditer(line):
        g = m.lastgroup
        if g == "dec_v":
            dec_fields[m.group("dec_k")] = int(m.group("dec_v"))
        elif g == "hex_v":
            hex_fields[m.group("hex_k")] = int(m.group("hex_v"), 16)
        elif g == "resp_v":
            sensor_resp = RESP_MAP.get(
                m.group("resp_v").decode("ascii"), RESP_NONE
            )
        elif g == "flags_v":
            tcp_flags_raw = m.group("flags_v")

    pkt_len = dec_fields.get(b"Len")
    ip_id   = dec_fields.get(b"ID")
    ttl     = dec_fields.get(b"TTL")
    dg_len  = dec_fields.get(b"DgLen")
    tos     = hex_fields.get(b"TOS")

    tcp_flags = tcp_seq = tcp_ack = tcp_win = tcp_len = None
    icmp_type = icmp_code = None
    if proto == PROTO_TCP:
        if tcp_flags_raw is not None:
            tcp_flags = _flag_mask_to_int(tcp_flags_raw)
        tcp_seq = hex_fields.get(b"Seq")
        tcp_ack = hex_fields.get(b"Ack")
        tcp_win = hex_fields.get(b"Win")
        tcp_len = dec_fields.get(b"TcpLen")
    elif proto == PROTO_ICMP:
        icmp_type = dec_fields.get(b"Type")
        icmp_code = dec_fields.get(b"Code")

    m_pkt = _PKTDATA_RE.search(line)
    pkt_b64 = m_pkt.group(1) if m_pkt else None

    return {
        "ts_date": m_ts.group(1).decode("ascii"),
        "ts_time": m_ts.group(2).decode("ascii"),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "pkt_len": pkt_len,
        "ip_id": ip_id,
        "tos": tos,
        "ttl": ttl,
        "dg_len": dg_len,
        "tcp_flags": tcp_flags,
        "tcp_seq": tcp_seq,
        "tcp_ack": tcp_ack,
        "tcp_win": tcp_win,
        "tcp_len": tcp_len,
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "sensor_resp": sensor_resp,
        "pkt_b64": pkt_b64,
    }


# ----------------------------------------------------------------------
# Binary packet parsing
# ----------------------------------------------------------------------

def extract_payload(raw: bytes, proto: int) -> bytes | None:
    """Skip Ethernet + IPv4 + L4 headers, return the L7 payload bytes.

    Returns ``b""`` if frame is well-formed but carries no payload, or
    ``None`` if the frame is malformed/too short.
    """
    if len(raw) < 34:  # Eth(14) + min IPv4(20)
        return None

    # The first 14 bytes are Ethernet; skip them.
    # Sensor always logs Ethernet II frames (confirmed during profiling).
    ip = raw[14:]
    if not ip:
        return None
    ver_ihl = ip[0]
    if (ver_ihl >> 4) != 4:
        return None  # not IPv4 (the corpus is ~100% IPv4)
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    total_len = struct.unpack("!H", ip[2:4])[0]
    # Trim to advertised total length (handles padding from the wire).
    ip = ip[: min(total_len, len(ip))]
    l4 = ip[ihl:]

    if proto == PROTO_TCP:
        if len(l4) < 20:
            return None
        data_offset = (l4[12] >> 4) * 4
        if data_offset < 20 or len(l4) < data_offset:
            return None
        return l4[data_offset:]
    if proto == PROTO_UDP:
        if len(l4) < 8:
            return None
        return l4[8:]
    if proto == PROTO_ICMP:
        if len(l4) < 8:
            return None
        return l4[8:]
    return None


# ----------------------------------------------------------------------
# L7 fingerprinting
# ----------------------------------------------------------------------

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
                 b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ", b"PROPFIND ")
_SSH_PREFIX = b"SSH-"
_BITTORRENT_PREFIX = b"\x13BitTorrent protocol"
_SMB_PREFIXES = (b"\xffSMB", b"\xfeSMB")
_HTTP_RESP_PREFIX = b"HTTP/"

# Mirai/IoT shell strings — used to detect dropper/recon stages.
_MIRAI_HINTS = (b"/bin/busybox", b"BUSYBOX", b"ECCHI", b"/tmp/.x", b";wget ",
                b"; tftp ", b"; chmod ", b"; sh ", b"/dev/null 2>&1",
                b"enable\r\n", b"system\r\n", b"shell\r\n")


def detect_l7(payload: bytes, src_port: int | None, dst_port: int | None) -> int:
    if not payload:
        return L7_UNKNOWN
    first = payload[:16]

    if first.startswith(_HTTP_METHODS) or first.startswith(_HTTP_RESP_PREFIX):
        return L7_HTTP
    if first.startswith(_SSH_PREFIX):
        return L7_SSH
    if payload.startswith(_BITTORRENT_PREFIX):
        return L7_BITTORRENT
    if any(payload.startswith(p) for p in _SMB_PREFIXES):
        return L7_SMB
    # TLS record: type(0x14-0x17) + version 0x03 0x0?
    if len(payload) >= 5 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
        return L7_TLS
    # RDP / TPKT (port 3389) starts with 0x03 0x00.
    if dst_port == 3389 and len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
        return L7_RDP
    # MongoDB wire protocol probe.
    if b"admin.$cmd" in payload[:64] or b"ismaster" in payload[:64]:
        return L7_MONGO
    # Redis inline commands.
    if first.startswith(b"PING\r\n") or first.startswith(b"INFO\r\n") or first.startswith(b"AUTH "):
        return L7_REDIS
    # MQTT CONNECT.
    if dst_port == 1883 and len(payload) >= 2 and (payload[0] & 0xF0) == 0x10:
        return L7_MQTT
    # FTP banners/commands.
    if first.startswith(b"220 ") or first.startswith(b"USER ") or first.startswith(b"PASS "):
        return L7_FTP if (dst_port == 21 or src_port == 21) else L7_FTP
    # SMTP.
    if first.startswith(b"EHLO ") or first.startswith(b"HELO ") or first.startswith(b"MAIL FROM:"):
        return L7_SMTP
    # IRC (text protocol).
    if first.startswith(b"NICK ") or first.startswith(b"USER ") or first.startswith(b"PRIVMSG "):
        return L7_IRC
    # Telnet: very loose, use port hint.
    if dst_port == 23 or src_port == 23:
        return L7_TELNET
    # VNC handshake.
    if first.startswith(b"RFB "):
        return L7_VNC
    # Mirai-style payload heuristics on busybox/wget/tftp/etc.
    if any(h in payload for h in _MIRAI_HINTS):
        return L7_MIRAI
    return L7_UNKNOWN


# ----------------------------------------------------------------------
# Lightweight L7 field extraction (best-effort, regex-driven)
# ----------------------------------------------------------------------

_HTTP_REQ_LINE = re.compile(rb"^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|TRACE|CONNECT|PROPFIND) ([^\s]+) HTTP/[0-9.]+")
_HTTP_HOST     = re.compile(rb"\r\nHost:\s*([^\r\n]+)", re.IGNORECASE)
_HTTP_UA       = re.compile(rb"\r\nUser-Agent:\s*([^\r\n]+)", re.IGNORECASE)
_HTTP_AUTH     = re.compile(rb"\r\nAuthorization:\s*([^\r\n]+)", re.IGNORECASE)
_HTTP_COOKIE   = re.compile(rb"\r\nCookie:\s*([^\r\n]+)", re.IGNORECASE)
_RDP_MSTSHASH  = re.compile(rb"mstshash=([\x20-\x7e]+?)\r\n")

_URL_RE        = re.compile(rb"\b(?:https?|ftp|tftp)://[A-Za-z0-9._~%!$&'()*+,;=:@/-]+", re.IGNORECASE)
_IPV4_RE       = re.compile(rb"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b")
_HEX_HASH_RE   = re.compile(rb"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
_DOMAIN_RE     = re.compile(rb"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})\b")
# Mirai-ish busybox patterns: wget/curl/tftp URL or IP.
_BUSYBOX_CMD   = re.compile(rb"(?:wget|curl|tftp(?:get)?|ftpget)\s+[^\s;|&]+", re.IGNORECASE)
# Telnet/RDP default-cred sequences: take any short line after username/password prompts.
_CRED_PAIR     = re.compile(rb"\b(?:user(?:name)?|login)[:=]\s*([\x20-\x7e]{1,32})\b.*?\b(?:pass(?:word)?|pw)[:=]\s*([\x20-\x7e]{1,32})\b",
                            re.IGNORECASE | re.DOTALL)

# Reserved/non-routable IPs we don't want as IOCs.
_PRIVATE_IP_RANGES = (
    (0x00000000, 0x00FFFFFF),    # 0.0.0.0/8
    (0x0A000000, 0x0AFFFFFF),    # 10/8
    (0x7F000000, 0x7FFFFFFF),    # 127/8
    (0xA9FE0000, 0xA9FEFFFF),    # 169.254/16
    (0xAC100000, 0xAC1FFFFF),    # 172.16/12
    (0xC0A80000, 0xC0A8FFFF),    # 192.168/16
    (0xE0000000, 0xFFFFFFFF),    # 224/4 multicast + 240/4 reserved
)


def _ip4_to_int(b: bytes) -> int:
    parts = b.split(b".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def _is_routable_ipv4(b: bytes) -> bool:
    try:
        n = _ip4_to_int(b)
    except Exception:
        return False
    for lo, hi in _PRIVATE_IP_RANGES:
        if lo <= n <= hi:
            return False
    return True


def _strings(payload: bytes, min_len: int = 4) -> list[bytes]:
    """Cheap printable-ASCII string extractor (no dependencies)."""
    out = []
    run = bytearray()
    for byte in payload:
        if 0x20 <= byte < 0x7F:
            run.append(byte)
        else:
            if len(run) >= min_len:
                out.append(bytes(run))
            run.clear()
    if len(run) >= min_len:
        out.append(bytes(run))
    return out


def parse_tls_clienthello(payload: bytes) -> tuple[str | None, list[int] | None, str | None]:
    """Best-effort ClientHello SNI / ciphersuites / version extraction.

    Returns (sni, ciphersuites_list, version) — any may be None.
    """
    try:
        if len(payload) < 11 or payload[0] != 0x16 or payload[5] != 0x01:
            return None, None, None
        # Skip TLS record (5) + handshake header (4) + client_version(2) + random(32) -> session_id_len
        p = 5 + 4 + 2 + 32
        sid_len = payload[p]; p += 1 + sid_len
        cs_len = struct.unpack_from("!H", payload, p)[0]; p += 2
        ciphersuites = []
        for i in range(0, cs_len, 2):
            cs = struct.unpack_from("!H", payload, p + i)[0]
            ciphersuites.append(cs)
        p += cs_len
        cm_len = payload[p]; p += 1 + cm_len
        if p + 2 > len(payload):
            return None, ciphersuites, None
        ext_total = struct.unpack_from("!H", payload, p)[0]; p += 2
        end = p + ext_total
        sni = None
        version_hex = None
        while p + 4 <= end and p + 4 <= len(payload):
            ext_type = struct.unpack_from("!H", payload, p)[0]
            ext_len = struct.unpack_from("!H", payload, p + 2)[0]
            ep = p + 4
            if ext_type == 0x00 and ep + 5 <= len(payload):  # server_name
                name_list_len = struct.unpack_from("!H", payload, ep)[0]
                np = ep + 2
                if np + 3 <= len(payload):
                    name_type = payload[np]
                    name_len = struct.unpack_from("!H", payload, np + 1)[0]
                    if name_type == 0 and np + 3 + name_len <= len(payload):
                        sni = payload[np + 3:np + 3 + name_len].decode("ascii", errors="replace")
            elif ext_type == 0x2b and ep + 1 <= len(payload):  # supported_versions
                ver_list_len = payload[ep]
                versions = []
                for i in range(0, ver_list_len, 2):
                    if ep + 1 + i + 2 <= len(payload):
                        v = struct.unpack_from("!H", payload, ep + 1 + i)[0]
                        versions.append(v)
                if versions:
                    version_hex = f"0x{max(versions):04x}"
            p = ep + ext_len
        return sni, ciphersuites, version_hex
    except Exception:
        return None, None, None


def extract_l7_fields(l7: int, payload: bytes) -> dict | None:
    """Return a dict of L7 fields, or None if nothing useful was extracted."""
    if not payload:
        return None
    fields: dict[str, Any] = {}
    if l7 == L7_HTTP:
        m = _HTTP_REQ_LINE.match(payload)
        if m:
            fields["method"] = m.group(1).decode("ascii", errors="replace")
            fields["uri"] = m.group(2).decode("ascii", errors="replace")
        mh = _HTTP_HOST.search(payload[:4096])
        if mh:
            fields["host"] = mh.group(1).decode("ascii", errors="replace").strip()
        mu = _HTTP_UA.search(payload[:4096])
        if mu:
            fields["user_agent"] = mu.group(1).decode("ascii", errors="replace").strip()
        mc = _HTTP_COOKIE.search(payload[:4096])
        if mc:
            fields["cookie"] = mc.group(1).decode("ascii", errors="replace").strip()
        ma = _HTTP_AUTH.search(payload[:4096])
        if ma:
            fields["auth"] = ma.group(1).decode("ascii", errors="replace").strip()
    elif l7 == L7_SSH:
        # First line ending in \n is the banner.
        line_end = payload.find(b"\n")
        if 4 < (line_end if line_end > 0 else len(payload)) < 256:
            banner = payload[: line_end if line_end > 0 else 256]
            fields["banner"] = banner.rstrip(b"\r").decode("ascii", errors="replace")
    elif l7 == L7_TLS:
        sni, ciphers, ver = parse_tls_clienthello(payload)
        if sni:    fields["sni"] = sni
        if ver:    fields["version"] = ver
        if ciphers:fields["ciphersuites"] = ciphers
    elif l7 == L7_RDP:
        mc = _RDP_MSTSHASH.search(payload)
        if mc:
            fields["mstshash"] = mc.group(1).decode("ascii", errors="replace")
    elif l7 == L7_BITTORRENT:
        # Bytes 20..28 = peer info hash bytes, 28..48 = peer ID.
        if len(payload) >= 48:
            fields["peer_id"] = payload[28:48].decode("ascii", errors="replace")
    elif l7 == L7_MIRAI:
        cmds = _BUSYBOX_CMD.findall(payload)
        if cmds:
            fields["busybox_cmds"] = [c.decode("ascii", errors="replace") for c in cmds[:16]]
    return fields or None


# ----------------------------------------------------------------------
# IOC mining (runs on every payload regardless of L7 detection)
# ----------------------------------------------------------------------

def mine_iocs(payload: bytes, l7: int, l7_fields: dict | None) -> list[tuple[int, str, str]]:
    """Return list of (ioc_kind, value, context). Context is a short snippet."""
    out: list[tuple[int, str, str]] = []
    if not payload:
        return out
    # Cap regex scan window — IOCs of interest occur in headers/banners.
    scan = payload[:4096]

    for m in _URL_RE.finditer(scan):
        url = m.group(0).decode("ascii", errors="replace")
        out.append((IOC_URL, url, ""))

    for m in _IPV4_RE.finditer(scan):
        if _is_routable_ipv4(m.group(0)):
            out.append((IOC_IPV4, m.group(0).decode("ascii"), ""))

    for m in _HEX_HASH_RE.finditer(scan):
        out.append((IOC_FILE_HASH, m.group(0).decode("ascii"), ""))

    for m in _DOMAIN_RE.finditer(scan):
        dom = m.group(0).decode("ascii", errors="replace").lower()
        if "." in dom and not dom.endswith((".local", ".lan", ".internal", ".arpa")):
            out.append((IOC_DOMAIN, dom, ""))

    for m in _BUSYBOX_CMD.finditer(scan):
        out.append((IOC_CMD, m.group(0).decode("ascii", errors="replace"), ""))

    for m in _CRED_PAIR.finditer(scan):
        out.append((IOC_CRED, f"{m.group(1).decode('ascii', 'replace')}:{m.group(2).decode('ascii', 'replace')}", ""))

    if l7_fields:
        if l7 == L7_HTTP:
            ua = l7_fields.get("user_agent")
            if ua: out.append((IOC_USER_AGENT, ua, ""))
            host = l7_fields.get("host")
            if host: out.append((IOC_HTTP_HOST, host, ""))
            uri = l7_fields.get("uri")
            if uri:  out.append((IOC_HTTP_URI, uri, ""))
        elif l7 == L7_SSH:
            b = l7_fields.get("banner")
            if b: out.append((IOC_SSH_BANNER, b, ""))
        elif l7 == L7_TLS:
            sni = l7_fields.get("sni")
            if sni: out.append((IOC_TLS_SNI, sni, ""))
        elif l7 == L7_RDP:
            h = l7_fields.get("mstshash")
            if h: out.append((IOC_MSTSHASH, h, ""))

    return out


# ----------------------------------------------------------------------
# Per-line driver (composes everything above)
# ----------------------------------------------------------------------

def process_line(line: bytes) -> tuple | None:
    """Returns:
        (packet_row, blob_row_or_None, l7_row_or_None, ioc_rows)

    All rows are plain dicts (Arrow conversion happens in the writer).
    blob_row is emitted at-most-once per payload_sha256 *within this worker
    batch*; the writer does a final dedup pass across workers.
    """
    fields = parse_text_fields(line)
    if fields is None:
        return None

    iso_str = f"{fields['ts_date']}T{fields['ts_time']}+00:00"
    # PyArrow wants a tz-aware datetime to materialize timestamp('us', UTC).
    ts = datetime.fromisoformat(iso_str)
    day_key = fields["ts_date"]  # YYYY-MM-DD, used by writer for partitioning
    pkt_b64 = fields["pkt_b64"]
    payload_sha256 = None
    payload_len = 0
    l7_proto = L7_UNKNOWN
    l7_fields = None
    iocs: list[tuple[int, str, str]] = []
    blob_row = None

    if pkt_b64:
        try:
            raw = base64.b64decode(pkt_b64, validate=False)
        except Exception:
            raw = None
        if raw is not None:
            payload = extract_payload(raw, fields["proto"])
            if payload:
                payload_len = len(payload)
                payload_sha256 = hashlib.sha256(payload).digest()
                l7_proto = detect_l7(payload, fields["src_port"], fields["dst_port"])
                l7_fields = extract_l7_fields(l7_proto, payload)
                iocs = mine_iocs(payload, l7_proto, l7_fields)
                # Storage cap: keep first 2 KB of payload. Anything actionable
                # (HTTP headers, TLS ClientHello, dropper command, banners) lives
                # in the first few hundred bytes; trimming bounds writer memory.
                clipped = payload[:2048]
                blob_row = {
                    "payload_sha256": payload_sha256,
                    "payload_len": payload_len,
                    "l7_proto": l7_proto,
                    "bytes": clipped,
                    "strings": [s.decode("ascii", errors="replace") for s in _strings(clipped)[:32]],
                }

    packet_row = {
        "ts": ts,
        "day": day_key,
        "src_ip": fields["src_ip"],
        "src_port": fields["src_port"],
        "dst_ip": fields["dst_ip"],
        "dst_port": fields["dst_port"],
        "proto": fields["proto"],
        "pkt_len": fields["pkt_len"],
        "ip_id": fields["ip_id"],
        "tos": fields["tos"],
        "ttl": fields["ttl"],
        "dg_len": fields["dg_len"],
        "tcp_flags": fields["tcp_flags"],
        "tcp_seq": fields["tcp_seq"],
        "tcp_ack": fields["tcp_ack"],
        "tcp_win": fields["tcp_win"],
        "tcp_len": fields["tcp_len"],
        "icmp_type": fields["icmp_type"],
        "icmp_code": fields["icmp_code"],
        "sensor_resp": fields["sensor_resp"],
        "payload_sha256": payload_sha256,
        "payload_len": payload_len,
        "l7_proto": l7_proto,
    }

    l7_row = None
    if l7_fields:
        l7_row = {
            "ts": ts,
            "day": day_key,
            "src_ip": fields["src_ip"],
            "dst_port": fields["dst_port"],
            "l7_proto": l7_proto,
            "payload_sha256": payload_sha256,
            # Store as JSON-encoded string so we can keep the schema flat.
            # Downstream can json_extract via DuckDB.
            "fields_json": _json_dump(l7_fields),
        }

    ioc_rows = []
    for kind, value, ctx in iocs:
        ioc_rows.append({
            "ts": ts,
            "day": day_key,
            "src_ip": fields["src_ip"],
            "ioc_kind": kind,
            "value": value[:512],  # belt-and-suspenders cap
            "context": ctx,
            "l7_proto": l7_proto,
            "payload_sha256": payload_sha256,
        })

    return packet_row, blob_row, l7_row, ioc_rows


def _json_dump(obj: dict) -> str:
    """Tiny JSON encoder (avoids importing json in hot path? — actually fine)."""
    import json
    return json.dumps(obj, default=str, separators=(",", ":"))


# ----------------------------------------------------------------------
# Worker entry point
# ----------------------------------------------------------------------

def worker_chunk(chunk: list[bytes]) -> tuple[list, list, list, list]:
    """Process a chunk of input lines. Returns four parallel lists."""
    packets, blobs, l7s, iocs = [], [], [], []
    seen_sha = set()  # local dedup within this chunk
    for line in chunk:
        r = process_line(line)
        if r is None:
            continue
        p, b, l, i = r
        packets.append(p)
        if b is not None:
            sha = b["payload_sha256"]
            if sha not in seen_sha:
                seen_sha.add(sha)
                blobs.append(b)
        if l is not None:
            l7s.append(l)
        if i:
            iocs.extend(i)
    return packets, blobs, l7s, iocs


def _worker_loop(task_q: mp.Queue, out_q: mp.Queue) -> None:
    """Standalone worker: pull chunks from task_q, push results to out_q.

    Exits when it receives None from task_q.
    """
    while True:
        chunk = task_q.get()
        if chunk is None:
            break
        result = worker_chunk(chunk)
        out_q.put(result)


# ----------------------------------------------------------------------
# PyArrow schemas
# ----------------------------------------------------------------------

PACKETS_SCHEMA = pa.schema([
    ("ts",             pa.timestamp("us", tz="UTC")),
    ("src_ip",         pa.string()),
    ("src_port",       pa.uint16()),
    ("dst_ip",         pa.string()),
    ("dst_port",       pa.uint16()),
    ("proto",          pa.uint8()),
    ("pkt_len",        pa.uint16()),
    ("ip_id",          pa.uint16()),
    ("tos",            pa.uint8()),
    ("ttl",            pa.uint8()),
    ("dg_len",         pa.uint16()),
    ("tcp_flags",      pa.uint8()),
    ("tcp_seq",        pa.uint32()),
    ("tcp_ack",        pa.uint32()),
    ("tcp_win",        pa.uint32()),
    ("tcp_len",        pa.uint16()),
    ("icmp_type",      pa.uint8()),
    ("icmp_code",      pa.uint8()),
    ("sensor_resp",    pa.uint8()),
    ("payload_sha256", pa.binary(32)),
    ("payload_len",    pa.uint16()),
    ("l7_proto",       pa.uint8()),
])

BLOBS_SCHEMA = pa.schema([
    ("payload_sha256", pa.binary(32)),
    ("payload_len",    pa.uint16()),
    ("l7_proto",       pa.uint8()),
    ("bytes",          pa.binary()),
    ("strings",        pa.list_(pa.string())),
])

L7_SCHEMA = pa.schema([
    ("ts",             pa.timestamp("us", tz="UTC")),
    ("src_ip",         pa.string()),
    ("dst_port",       pa.uint16()),
    ("l7_proto",       pa.uint8()),
    ("payload_sha256", pa.binary(32)),
    ("fields_json",    pa.string()),
])

IOCS_SCHEMA = pa.schema([
    ("ts",             pa.timestamp("us", tz="UTC")),
    ("src_ip",         pa.string()),
    ("ioc_kind",       pa.uint8()),
    ("value",          pa.string()),
    ("context",        pa.string()),
    ("l7_proto",       pa.uint8()),
    ("payload_sha256", pa.binary(32)),
])


# ----------------------------------------------------------------------
# Streaming daily Parquet writer
# ----------------------------------------------------------------------
#
# Memory discipline: never materialize a full part-file in memory. Instead
# keep one open ParquetWriter per (table, day) and flush small row groups
# (BATCH_ROWS) as they fill. Closing a day's writers happens lazily when a
# newer day starts emitting rows (the merged log is globally time-sorted).

BATCH_ROWS_PACKETS = 5000   # ~30 cols * 5000 ~ small enough to keep RSS flat
BATCH_ROWS_BLOBS   = 2000   # blobs carry bytes; smaller batch to cap memory
BATCH_ROWS_L7      = 5000
BATCH_ROWS_IOCS    = 10000  # iocs are tiny strings


class StreamingTableWriter:
    """One Parquet file per (table, day): each flush appends a row group to a
    persistent ParquetWriter rather than emitting a new file, so a day with
    millions of rows is one file of many row groups instead of hundreds of
    tiny part-files.  Memory stays flat -- only one ``batch_rows`` buffer is
    materialized at a time; the writer just accumulates (small) footer
    metadata until the day is closed.

    The merged log is ~time-sorted, so a day's writer is opened on first row
    and closed (finalized) by ``close_day`` once that day goes idle.  If a
    finalized day reappears later (clock skew / out-of-order), a fresh
    ``part-NNNN`` file is started so nothing is clobbered."""

    def __init__(self, base: Path, label: str, schema: pa.Schema,
                 batch_rows: int, rows_per_part: int = 500_000):
        self.base = base
        self.label = label
        self.schema = schema
        self.batch_rows = batch_rows          # row-group size (memory bound)
        self.rows_per_part = max(batch_rows, rows_per_part)  # file roll size
        self._buffers: dict[str, list[dict]] = {}
        self._writers: dict[str, pq.ParquetWriter] = {}
        self._cur_rows: dict[str, int] = {}   # rows in the day's open file
        self._part_no: dict[str, int] = {}
        self._row_counts: dict[str, int] = {}

    def add(self, row: dict) -> None:
        day = row.pop("day")
        buf = self._buffers.setdefault(day, [])
        buf.append(row)
        if len(buf) >= self.batch_rows:
            self._flush_batch(day)

    def _open(self, day: str) -> pq.ParquetWriter:
        n = self._part_no.get(day, 0)
        out_dir = self.base / self.label / f"dt={day}"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"part-{n:04d}.parquet"
        w = pq.ParquetWriter(out_path, self.schema,
                             compression="zstd", compression_level=3)
        self._writers[day] = w
        self._cur_rows[day] = 0
        return w

    def _close(self, day: str) -> None:
        w = self._writers.pop(day, None)
        if w is not None:
            w.close()
            self._part_no[day] = self._part_no.get(day, 0) + 1
        self._cur_rows.pop(day, None)

    def _flush_batch(self, day: str) -> None:
        buf = self._buffers.get(day)
        if not buf:
            return
        writer = self._writers.get(day) or self._open(day)
        table = pa.Table.from_pylist(buf, schema=self.schema)
        writer.write_table(table)  # appends one row group; releases the batch
        del table
        self._cur_rows[day] += len(buf)
        self._row_counts[day] = self._row_counts.get(day, 0) + len(buf)
        buf.clear()
        # Roll to a fresh part file once this one reaches rows_per_part.
        if self._cur_rows[day] >= self.rows_per_part:
            self._close(day)

    def close_day(self, day: str) -> None:
        self._flush_batch(day)
        self._close(day)
        self._buffers.pop(day, None)

    def close_all(self) -> None:
        for day in list(set(self._buffers) | set(self._writers)):
            self.close_day(day)

    def stats(self) -> dict[str, int]:
        return dict(self._row_counts)


def writer_loop(q: mp.Queue, out_base: Path, idle_close_after: int, stats_q: mp.Queue, max_blob_dedup: int = 20_000_000, rows_per_part: int = 500_000) -> None:
    import gc
    gc.set_threshold(1000, 10, 10)  # more aggressive GC for the writer

    """Consume worker batches from ``q``. One streaming ParquetWriter per
    (table, day), rolled every ``rows_per_part`` rows. Closes a day's writers
    once ``idle_close_after`` consecutive batches arrive with no rows for it.
    """
    packets_w = StreamingTableWriter(out_base, "packets",       PACKETS_SCHEMA, BATCH_ROWS_PACKETS, rows_per_part)
    blobs_w   = StreamingTableWriter(out_base, "payload_blobs", BLOBS_SCHEMA,   BATCH_ROWS_BLOBS,   rows_per_part)
    l7_w      = StreamingTableWriter(out_base, "l7_events",     L7_SCHEMA,      BATCH_ROWS_L7,      rows_per_part)
    iocs_w    = StreamingTableWriter(out_base, "iocs",          IOCS_SCHEMA,    BATCH_ROWS_IOCS,    rows_per_part)

    # Global blob dedup using truncated 64-bit keys (first 8 bytes of SHA-256).
    # Collision probability with 30M entries in 2^64 space is ~2.4e-8.
    # int-keyed set uses ~28 bytes/entry vs ~90 bytes for bytes(32), saving
    # ~60% memory (~1 GB instead of ~3 GB at 30M entries).
    global_blob_sha: set[int] = set()

    # Track per-day idle counters so we can close yesterday's writers once a
    # new day starts streaming. Idle counter increments on every batch that
    # carries no rows for that day; resets when a row lands.
    day_idle: dict[str, int] = {}
    seen_days: set[str] = set()

    total = {"packets": 0, "blobs": 0, "l7": 0, "iocs": 0}
    t0 = time.time()
    last_report = t0

    while True:
        item = q.get()
        if item is None:
            break
        packets, blobs, l7s, iocs = item
        days_touched: set[str] = set()

        for row in packets:
            day = row["day"]
            days_touched.add(day)
            packets_w.add(row)
        total["packets"] += len(packets)

        for row in l7s:
            day = row["day"]
            days_touched.add(day)
            l7_w.add(row)
        total["l7"] += len(l7s)

        for row in iocs:
            day = row["day"]
            days_touched.add(day)
            iocs_w.add(row)
        total["iocs"] += len(iocs)

        # Blobs are sha-keyed, not time-keyed; partition by the day we first
        # encountered each sha so the file layout stays consistent.
        for row in blobs:
            sha = row["payload_sha256"]
            sha_key = int.from_bytes(sha[:8], "big")
            if sha_key in global_blob_sha:
                continue
            global_blob_sha.add(sha_key)
            if len(global_blob_sha) >= max_blob_dedup:
                print(f"[writer] blob dedup set hit {max_blob_dedup:,} entries, "
                      f"clearing to reclaim memory", file=sys.stderr)
                global_blob_sha.clear()
            day = next(iter(days_touched), None) or "unknown"
            row["day"] = day
            blobs_w.add(row)
            total["blobs"] += 1

        # Idle accounting: increment idle counter for known days that didn't
        # see any rows in this batch. Close writers for days idle long enough.
        for d in days_touched:
            day_idle[d] = 0
            seen_days.add(d)
        for d in list(day_idle.keys()):
            if d in days_touched:
                continue
            day_idle[d] += 1
            if day_idle[d] >= idle_close_after:
                packets_w.close_day(d)
                blobs_w.close_day(d)
                l7_w.close_day(d)
                iocs_w.close_day(d)
                day_idle.pop(d, None)

        now = time.time()
        if now - last_report >= 5:
            elapsed = now - t0
            rate = total["packets"] / elapsed if elapsed else 0
            try:
                import resource
                rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
            except Exception:
                rss_mb = 0
            print(f"[writer] packets={total['packets']:,} blobs={total['blobs']:,} "
                  f"l7={total['l7']:,} iocs={total['iocs']:,} "
                  f"{rate:,.0f}/s elapsed={elapsed:,.0f}s open_days={len(day_idle)} "
                  f"seen_days={len(seen_days)} rss={rss_mb:.0f}MB",
                  file=sys.stderr)
            last_report = now
            gc.collect()

    # Final flush + close.
    packets_w.close_all()
    blobs_w.close_all()
    l7_w.close_all()
    iocs_w.close_all()

    stats_q.put({**total, "files": len(seen_days), "elapsed_s": time.time() - t0})


# ----------------------------------------------------------------------
# Main entry
# ----------------------------------------------------------------------

def stream_input(path: Path, max_lines: int) -> Iterable[bytes]:
    """Yield raw bytes lines (without the ISO_UTC\\t prefix we added, but with the
    raw syslog content)."""
    p = subprocess.Popen(["zcat", str(path)], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, bufsize=1 << 22)
    n = 0
    try:
        for raw in p.stdout:
            # Each line is "<ISO>\t<rest>\n"; we only need the rest.
            tab = raw.find(b"\t")
            if tab == -1:
                continue
            yield raw[tab + 1: -1] if raw.endswith(b"\n") else raw[tab + 1:]
            n += 1
            if max_lines and n >= max_lines:
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


def chunks(it: Iterable[bytes], size: int) -> Iterable[list[bytes]]:
    buf = []
    for x in it:
        buf.append(x)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", default=str(Path.home() / "git/SensorGrind_AI/data/merged.log.gz"))
    ap.add_argument("--output", default=str(Path.home() / "git/SensorGrind_AI/output/parquet"))
    # Worker default was capped at 6 to dodge an OOM in the writer process
    # (writer accumulated full Pool result cache when it couldn't keep up).
    # That bug was fixed 2026-05-27 by switching to explicit Process workers
    # + bounded queues, so we can safely scale workers with the host.
    ap.add_argument("--workers", type=int,
                    default=max(2, (os.cpu_count() or 4) - 2))
    ap.add_argument("--chunk-lines", type=int, default=4000,
                    help="Lines per worker chunk. Larger = less IPC overhead, "
                         "more memory per inflight chunk.")
    ap.add_argument("--rows-per-part", type=int, default=500_000,
                    help="(legacy; no longer used) preserved for backwards CLI compat.")
    ap.add_argument("--idle-close-after", type=int, default=4,
                    help="Close a day's parquet writers after this many consecutive "
                         "queue batches contain no rows for that day.")
    ap.add_argument("--max-lines", type=int, default=0,
                    help="Stop after N lines (0 = all). Use for smoke tests.")
    ap.add_argument("--max-blob-dedup", type=int, default=20_000_000,
                    help="Max entries in the blob dedup set. Once reached, "
                         "the set is cleared and refilled from that point forward "
                         "(some cross-batch duplicates may be written).")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_base = Path(args.output)
    out_base.mkdir(parents=True, exist_ok=True)

    if not in_path.exists():
        print(f"input not found: {in_path}", file=sys.stderr)
        return 2

    print(f"[info] input:  {in_path}  ({in_path.stat().st_size/1e9:.2f} GB)")
    print(f"[info] output: {out_base}")
    print(f"[info] workers={args.workers}  chunk={args.chunk_lines}  "
          f"idle_close_after={args.idle_close_after}  max_lines={args.max_lines or 'all'}")

    task_q: mp.Queue = mp.Queue(maxsize=args.workers * 2)
    out_q: mp.Queue = mp.Queue(maxsize=args.workers * 2)
    stats_q: mp.Queue = mp.Queue()
    writer = mp.Process(target=writer_loop,
                        args=(out_q, out_base, args.idle_close_after, stats_q,
                              args.max_blob_dedup, args.rows_per_part),
                        daemon=False)
    writer.start()

    workers = []
    for _ in range(args.workers):
        w = mp.Process(target=_worker_loop, args=(task_q, out_q), daemon=True)
        w.start()
        workers.append(w)

    t0 = time.time()
    line_iter = stream_input(in_path, args.max_lines)
    for chunk in chunks(line_iter, args.chunk_lines):
        task_q.put(chunk)
        if not writer.is_alive():
            print("[error] writer process died, aborting", file=sys.stderr)
            break

    for _ in workers:
        task_q.put(None)
    for w in workers:
        w.join()

    out_q.put(None)
    writer.join()
    stats = stats_q.get(timeout=5)
    print(f"[done] {time.time() - t0:.1f}s wall  "
          f"packets={stats['packets']:,} blobs={stats['blobs']:,} "
          f"l7={stats['l7']:,} iocs={stats['iocs']:,} "
          f"parts={stats['files']:,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

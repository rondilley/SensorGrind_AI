#!/usr/bin/env python3
"""
protocolanomaly - TCP/IP protocol state-machine and combination anomalies.

What it computes
----------------
1. Per src->(dst_port) "state machine" sketch: did the sequence start with
   SYN, did it complete the handshake, did the same src->port pair use both
   SYN+payload (premature data) and ACK-only (mid-stream injection)?
2. Mid-stream payload injection: ACK-only or PA packet to a (src,dst_port)
   pair that never saw a SYN from that src.
3. Cross-protocol combos per source IP: which sources mix TCP+UDP+ICMP, or
   send the same payload to different L4 protocols.
4. Payload-bearing ICMP (ICMP echo with non-trivial payload often signals
   tunneling or covert channels).
5. Dst-port-on-wrong-proto: e.g. UDP packets to port 22 (SSH-typical),
   TCP packets to port 53 (DNS-typical, though valid).

Output: output/reports/protocolanomaly/*.parquet + .md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


STATE_SCHEMA = pa.schema([
    ("anomaly_kind",  pa.string()),
    ("packets",       pa.uint64()),
    ("distinct_ips",  pa.uint32()),
])
CROSSPROTO_SCHEMA = pa.schema([
    ("src_ip",            pa.string()),
    ("uses_tcp",          pa.bool_()),
    ("uses_udp",          pa.bool_()),
    ("uses_icmp",         pa.bool_()),
    ("payload_tcp",       pa.uint64()),
    ("payload_udp",       pa.uint64()),
    ("payload_icmp",      pa.uint64()),
    ("multi_proto_score", pa.uint8()),
])
WRONGPROTO_SCHEMA = pa.schema([
    ("proto",     pa.string()),
    ("dst_port",  pa.uint16()),
    ("packets",   pa.uint64()),
    ("ips",       pa.uint32()),
    ("note",      pa.string()),
])


def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="16GB")
    con.execute("SET preserve_insertion_order=false")
    lib.register_views(con)
    out_dir = lib.REPORTS / "protocolanomaly"
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- state-machine sketch (per src,dst_port) ---
    print("[protoanom] tcp state-machine sketch (per src,dst_port)...",
          file=sys.stderr)
    sketch_rows = con.execute("""
        WITH pair AS (
            SELECT src_ip, dst_port,
                   bool_or(tcp_flags = 2)            AS saw_syn,
                   bool_or(tcp_flags & 16 != 0 AND tcp_flags & 2 = 0
                           AND payload_len > 0)      AS saw_mid_payload,
                   bool_or(tcp_flags = 2 AND payload_len > 0)
                                                     AS syn_with_payload,
                   bool_or(tcp_flags & 1 != 0 AND tcp_flags & 16 = 0)
                                                     AS fin_no_ack,
                   count(*) AS pkts
            FROM packets WHERE proto = 6 AND dst_port IS NOT NULL
            GROUP BY src_ip, dst_port
        )
        SELECT
            sum(CASE WHEN saw_mid_payload AND NOT saw_syn THEN pkts ELSE 0 END) AS mid_inject_pkts,
            count(*) FILTER (WHERE saw_mid_payload AND NOT saw_syn)             AS mid_inject_pairs,
            sum(CASE WHEN syn_with_payload THEN pkts ELSE 0 END)                AS syn_payload_pkts,
            count(*) FILTER (WHERE syn_with_payload)                            AS syn_payload_pairs,
            sum(CASE WHEN fin_no_ack THEN pkts ELSE 0 END)                      AS fin_alone_pkts,
            count(*) FILTER (WHERE fin_no_ack)                                  AS fin_alone_pairs
        FROM pair
    """).fetchone()
    mid_pkts, mid_pairs, sp_pkts, sp_pairs, fa_pkts, fa_pairs = sketch_rows

    state_rows = [
        {"anomaly_kind": "Mid-stream payload (ACK/PA without prior SYN)",
         "packets": int(mid_pkts or 0), "distinct_ips": int(mid_pairs or 0)},
        {"anomaly_kind": "SYN with payload (premature data)",
         "packets": int(sp_pkts or 0), "distinct_ips": int(sp_pairs or 0)},
        {"anomaly_kind": "FIN without ACK (unsolicited teardown)",
         "packets": int(fa_pkts or 0), "distinct_ips": int(fa_pairs or 0)},
    ]
    pq.write_table(pa.Table.from_pylist(state_rows, schema=STATE_SCHEMA),
                   out_dir / "tcp_state.parquet",
                   compression="zstd", compression_level=3)

    # --- cross-protocol mix per source (top by multi-proto-score) ---
    print("[protoanom] cross-protocol mix per source IP...", file=sys.stderr)
    cross_rows = con.execute("""
        SELECT src_ip,
               bool_or(proto = 6)  AS uses_tcp,
               bool_or(proto = 17) AS uses_udp,
               bool_or(proto = 1)  AS uses_icmp,
               sum(CASE WHEN proto = 6  AND payload_len > 0 THEN 1 ELSE 0 END) AS pl_tcp,
               sum(CASE WHEN proto = 17 AND payload_len > 0 THEN 1 ELSE 0 END) AS pl_udp,
               sum(CASE WHEN proto = 1  AND payload_len > 0 THEN 1 ELSE 0 END) AS pl_icmp
        FROM packets GROUP BY src_ip
        HAVING (bool_or(proto=6)::INT + bool_or(proto=17)::INT + bool_or(proto=1)::INT) >= 2
    """).fetchall()
    cross_out = []
    for ip, t, u, i, p_t, p_u, p_i in cross_rows:
        score = int(t) + int(u) + int(i)
        cross_out.append({
            "src_ip": ip, "uses_tcp": bool(t), "uses_udp": bool(u),
            "uses_icmp": bool(i),
            "payload_tcp": int(p_t), "payload_udp": int(p_u),
            "payload_icmp": int(p_i),
            "multi_proto_score": score,
        })
    cross_out.sort(key=lambda r: (-r["multi_proto_score"],
                                  -(r["payload_tcp"] + r["payload_udp"] + r["payload_icmp"])))
    pq.write_table(pa.Table.from_pylist(cross_out, schema=CROSSPROTO_SCHEMA),
                   out_dir / "cross_proto.parquet",
                   compression="zstd", compression_level=3)

    # --- payload-bearing ICMP ---
    print("[protoanom] payload-bearing ICMP (covert-channel hint)...",
          file=sys.stderr)
    icmp_payload = con.execute("""
        SELECT count(*) AS pkts, count(DISTINCT src_ip) AS ips
        FROM packets WHERE proto = 1 AND payload_len > 8
    """).fetchone()
    icmp_rows = [{"anomaly_kind": "ICMP with non-trivial payload (>8B)",
                  "packets": int(icmp_payload[0] or 0),
                  "distinct_ips": int(icmp_payload[1] or 0)}]
    pq.write_table(pa.Table.from_pylist(icmp_rows, schema=STATE_SCHEMA),
                   out_dir / "icmp_payload.parquet",
                   compression="zstd", compression_level=3)

    # --- wrong-protocol-for-port (common indicators of scanning/abuse) ---
    print("[protoanom] dst-port-on-wrong-proto...", file=sys.stderr)
    wp_rows = con.execute("""
        SELECT proto, dst_port, count(*) AS packets, count(DISTINCT src_ip) AS ips
        FROM packets
        WHERE
          (proto = 17 AND dst_port IN (22, 80, 443, 3389, 23))   -- UDP scanning on TCP-typical
          OR (proto = 6  AND dst_port IN (53, 161, 5353, 1900))   -- TCP probes to UDP-typical
        GROUP BY proto, dst_port
        ORDER BY packets DESC LIMIT 50
    """).fetchall()
    NOTE = {
        (17, 22):  "UDP to SSH port - unusual probe",
        (17, 80):  "UDP to HTTP port - scan / amp reflection",
        (17, 443): "UDP to TLS port - QUIC probe or scan",
        (17, 3389): "UDP to RDP port - probe / amp",
        (17, 23):  "UDP to telnet port - very rare",
        (6, 53):   "TCP to DNS port - zone-xfer attempt",
        (6, 161):  "TCP to SNMP port - unusual",
        (6, 5353): "TCP to mDNS port - unusual",
        (6, 1900): "TCP to SSDP port - unusual",
    }
    wp_out = []
    for p, port, pkts, ips in wp_rows:
        wp_out.append({
            "proto": lib.PROTO_NAME.get(int(p), str(p)),
            "dst_port": int(port), "packets": int(pkts), "ips": int(ips),
            "note": NOTE.get((int(p), int(port)), ""),
        })
    pq.write_table(pa.Table.from_pylist(wp_out, schema=WRONGPROTO_SCHEMA),
                   out_dir / "wrong_proto_port.parquet",
                   compression="zstd", compression_level=3)

    con.close()

    md = [
        "# protocolanomaly - TCP state-machine + cross-protocol oddities", "",
        "## TCP state-machine anomalies",
        "",
        "_Each row counts packets whose place in the connection state machine "
        "doesn't make sense.  Mid-stream payloads (no prior SYN from that src) "
        "indicate either packet-level spoofing or sensor-side state loss; "
        "SYN-with-payload is a TCP spec violation often produced by raw-socket "
        "scanners; FIN-without-ACK is an unsolicited teardown._",
        "",
        "| anomaly | packets | (src,dst_port) pairs |",
        "| --- | --- | --- |",
    ]
    for r in state_rows + icmp_rows:
        md.append(f"| {r['anomaly_kind']} | {r['packets']:,} | "
                  f"{r['distinct_ips']:,} |")

    md.extend(["",
               "## Wrong-protocol-for-port",
               "",
               "_TCP traffic to UDP-typical ports (DNS/SNMP/mDNS/SSDP) and "
               "UDP traffic to TCP-typical ports (SSH/HTTP/RDP).  Often a "
               "fingerprintable scanner trait or attempted amp/reflection._",
               "",
               "| proto | dst_port | packets | ips | note |",
               "| --- | --- | --- | --- | --- |"])
    for r in wp_out:
        md.append(f"| {r['proto']} | {r['dst_port']} | "
                  f"{r['packets']:,} | {r['ips']:,} | {r['note']} |")

    md.extend(["", "## Top 40 cross-protocol senders",
               "",
               "_Sources that use 2 or 3 of {TCP, UDP, ICMP} with payload.  "
               "Most attackers stay in one transport; multi-transport sources "
               "are either tooling (nmap -sU -sT) or genuinely strange._",
               "",
               "| src_ip | uses_tcp | uses_udp | uses_icmp | pl_tcp | pl_udp | pl_icmp |",
               "| --- | --- | --- | --- | --- | --- | --- |"])
    for r in cross_out[:40]:
        md.append(f"| {r['src_ip']} | {'TCP' if r['uses_tcp'] else ''} | "
                  f"{'UDP' if r['uses_udp'] else ''} | "
                  f"{'ICMP' if r['uses_icmp'] else ''} | "
                  f"{r['payload_tcp']:,} | {r['payload_udp']:,} | "
                  f"{r['payload_icmp']:,} |")

    (out_dir / "protocolanomaly.md").write_text("\n".join(md) + "\n")
    print(f"[protoanom] wrote {out_dir}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    return run(argparse.Namespace())


if __name__ == "__main__":
    sys.exit(main())

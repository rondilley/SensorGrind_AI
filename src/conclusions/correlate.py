#!/usr/bin/env python3
"""
conclusions/correlate - cross-analyzer pattern correlator.

Each rule joins across two or more analyzer outputs (the per-analyzer
parquets under output/reports/*/, plus risk + patterns) and emits one
finding row per matched pattern.  A finding carries:

  pattern_id, pattern_title, severity, category,
  src_ip_count, src_ips_sample, asns_sample, countries_sample,
  key_metrics (JSON), evidence_refs (JSON of {section, label}),
  report_anchor, first_seen, last_seen, detected_at.

The companion synthesize.py stage takes each finding and asks an LLM to
write the conclusion narrative (what / why-noteworthy / threat-model /
risk / recommended-action) and writes the final conclusions.parquet
that the comprehensive_report consumes.

Rules are intentionally small and self-contained.  Append new ones to
PATTERNS - each entry is a callable `fn(con) -> list[dict]`.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Callable

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib


OUT_DIR = lib.OUTPUT_DIR / "conclusions"

FINDING_SCHEMA = pa.schema([
    ("finding_id",       pa.string()),
    ("pattern_id",       pa.string()),
    ("pattern_title",    pa.string()),
    ("severity",         pa.string()),
    ("category",         pa.string()),
    ("src_ip_count",     pa.uint32()),
    ("src_ips_sample",   pa.string()),
    ("asns_sample",      pa.string()),
    ("countries_sample", pa.string()),
    ("key_metrics",      pa.string()),
    ("evidence_refs",    pa.string()),
    ("report_anchor",    pa.string()),
    ("first_seen",       pa.string()),
    ("last_seen",        pa.string()),
    ("detected_at",      pa.timestamp("us", tz="UTC")),
])


def _table(con, path: Path, view_name: str) -> bool:
    if not path.exists():
        return False
    con.execute(
        f"CREATE OR REPLACE VIEW {view_name} AS "
        f"SELECT * FROM read_parquet('{path.as_posix()}')"
    )
    return True


def _newest_risk_path() -> Path | None:
    base = lib.OUTPUT_DIR / "risk" / "ip_risk"
    if not base.exists():
        return None
    snaps = sorted((d for d in base.iterdir() if d.is_dir() and d.name.startswith("dt=")),
                   reverse=True)
    for s in snaps:
        rp = s / "risk.parquet"
        if rp.exists():
            return rp
    return None


def _short_id(pattern_id: str, src_ips: list[str]) -> str:
    h = hashlib.sha256(("|".join(sorted(src_ips)) + "|" + pattern_id).encode()).hexdigest()
    return f"{pattern_id}_{h[:10]}"


def _finding(
    pattern_id: str,
    pattern_title: str,
    severity: str,
    category: str,
    src_ips: list[str],
    asns: list[str] | None = None,
    countries: list[str] | None = None,
    key_metrics: dict | None = None,
    evidence_refs: list[dict] | None = None,
    report_anchor: str = "",
    first_seen: str = "",
    last_seen: str = "",
) -> dict:
    src_ips = [s for s in src_ips if s][:25]
    asns = [a for a in (asns or []) if a][:10]
    countries = [c for c in (countries or []) if c][:10]
    return {
        "finding_id":       _short_id(pattern_id, src_ips),
        "pattern_id":       pattern_id,
        "pattern_title":    pattern_title,
        "severity":         severity,
        "category":         category,
        "src_ip_count":     len(src_ips),
        "src_ips_sample":   ",".join(src_ips),
        "asns_sample":      "; ".join(asns),
        "countries_sample": ",".join(countries),
        "key_metrics":      json.dumps(key_metrics or {}, separators=(",", ":"), default=str),
        "evidence_refs":    json.dumps(evidence_refs or [], separators=(",", ":"), default=str),
        "report_anchor":    report_anchor,
        "first_seen":       first_seen,
        "last_seen":        last_seen,
        "detected_at":      _dt.datetime.now(_dt.timezone.utc),
    }


# Telco-relevant TCP ports.  TCP-side reconnaissance of any of these
# coincident with a real SCTP packet from the same source is the
# canonical SS7 / Diameter / SIGTRAN reconnaissance footprint.
TELCO_TCP_PORTS = {
    2123:  "GTP-C (GPRS Tunneling Protocol control)",
    2152:  "GTP-U (GPRS Tunneling Protocol user)",
    2905:  "M3UA (SS7 MTP3 User Adaptation)",
    2944:  "MEGACO/H.248 text",
    2945:  "MEGACO/H.248 binary",
    3868:  "Diameter",
    5060:  "SIP",
    5061:  "SIPS",
    5868:  "Diameter-DTLS",
    36412: "S1AP (LTE eNodeB-MME)",
    36422: "X2AP (LTE inter-eNodeB)",
    36443: "M2AP",
    36444: "M3AP",
}


# ----------------------------------------------------------------------
# Pattern rules
# ----------------------------------------------------------------------

def pat_telco_ss7_recon(con) -> list[dict]:
    """SCTP traffic from src_ips that are also doing TCP scans of telco ports."""
    out: list[dict] = []
    if not _have(con, "nonip_per_ip"):
        return out
    sctp = con.execute("""
        SELECT src_ip, packets, total_bytes, first_seen, last_seen
        FROM nonip_per_ip
        WHERE proto_num = 132
    """).fetchall()
    if not sctp:
        return out
    sctp_ips = [r[0] for r in sctp]

    telco_ports_list = sorted(TELCO_TCP_PORTS.keys())
    port_in = ",".join(str(p) for p in telco_ports_list)
    hits_by_ip: dict[str, dict] = {}

    in_clause = ("('" + sctp_ips[0] + "')" if len(sctp_ips) == 1
                 else str(tuple(sctp_ips)))

    if _have(con, "pkt_view"):
        rows = con.execute(f"""
            SELECT src_ip, dst_port, count(*) AS pkts
            FROM pkt_view
            WHERE src_ip IN {in_clause}
              AND proto = 6
              AND dst_port IN ({port_in})
            GROUP BY src_ip, dst_port
        """).fetchall()
        for sip, port, pkts in rows:
            d = hits_by_ip.setdefault(sip, {"ports": {}, "tcp_pkts": 0})
            d["ports"][int(port)] = int(pkts)
            d["tcp_pkts"] += int(pkts)

    if _have(con, "portscans"):
        rows = con.execute(f"""
            SELECT src_ip, top_ports, port_count, pkt_count, scan_type,
                   country_iso, asn_org
            FROM portscans
            WHERE src_ip IN {in_clause}
        """).fetchall()
        for sip, top_ports, port_count, pkt_count, scan_type, cc, asn in rows:
            telco_in_topports: list[int] = []
            if top_ports:
                for tok in top_ports.replace(";", ",").split(","):
                    tok = tok.strip()
                    if not tok:
                        continue
                    pstr = tok.split(":", 1)[0]
                    try:
                        p = int(pstr)
                    except ValueError:
                        continue
                    if p in TELCO_TCP_PORTS:
                        telco_in_topports.append(p)
            d = hits_by_ip.setdefault(sip, {"ports": {}, "tcp_pkts": 0})
            d.update({
                "scan_type": scan_type,
                "port_count": int(port_count),
                "tcp_total_pkts": int(pkt_count),
                "country": cc,
                "asn_org": asn,
            })
            for p in telco_in_topports:
                d["ports"].setdefault(p, 1)

    # Qualifying: SCTP arrival AND telco-TCP-port hit, OR SCTP arrival
    # from a confirmed scanner (SCTP at this honeypot is the smoking gun).
    qualifying = sorted(
        ((ip, d) for ip, d in hits_by_ip.items() if d.get("ports") or d.get("scan_type")),
        key=lambda kv: (-len(kv[1].get("ports", {})), -(kv[1].get("tcp_pkts") or 0)),
    )

    sctp_summary = {
        "sctp_distinct_srcs": len(sctp_ips),
        "sctp_packets":       sum(int(r[1]) for r in sctp),
        "telco_port_hits":    {ip: d.get("ports", {}) for ip, d in qualifying[:10]},
        "scanner_overlap":    sum(1 for _, d in qualifying if d.get("scan_type")),
        "telco_tcp_ports_seen_overall": sorted({
            p for _, d in hits_by_ip.items() for p in d.get("ports", {}).keys()
        }),
    }
    severity = "critical" if qualifying else "high"
    asns = list({d.get("asn_org", "") for _, d in qualifying})
    countries = list({d.get("country", "") for _, d in qualifying})

    out.append(_finding(
        pattern_id="telco_ss7_recon",
        pattern_title="Telco SS7 / Diameter / SIGTRAN reconnaissance footprint",
        severity=severity,
        category="telco-infrastructure",
        src_ips=[ip for ip, _ in qualifying] or sctp_ips,
        asns=asns,
        countries=countries,
        key_metrics=sctp_summary,
        evidence_refs=[
            {"section": "25", "label": "Non-TCP/UDP/ICMP IPv4 Traffic (nonipproto) - SCTP row"},
            {"section": "23", "label": "Cross-protocol senders + wrong-proto-for-port"},
            {"section": "1",  "label": "Risk tier of the sources"},
        ],
        report_anchor="#25-non-tcpudpicmp-ipv4-traffic-nonipproto",
        first_seen=min((r[3] for r in sctp), default=""),
        last_seen=max((r[4] for r in sctp), default=""),
    ))
    return out


def pat_routing_protocol_on_public_ip(con) -> list[dict]:
    """OSPF/EIGRP/PIM/VRRP arriving at a public honeypot is anomalous."""
    if not _have(con, "nonip_per_ip"):
        return []
    rows = con.execute("""
        SELECT proto_num, proto_name,
               count(DISTINCT src_ip) AS srcs,
               sum(packets) AS pkts,
               min(first_seen) AS fs, max(last_seen) AS ls,
               string_agg(DISTINCT src_ip, ',' ORDER BY src_ip) AS ips
        FROM nonip_per_ip
        WHERE proto_num IN (88, 89, 103, 112)
        GROUP BY proto_num, proto_name
    """).fetchall()
    if not rows:
        return []
    src_ips: list[str] = []
    metrics: dict = {}
    fs = ls = ""
    for num, name, srcs, pkts, f, l, ips in rows:
        metrics[name] = {"proto_num": int(num),
                         "distinct_srcs": int(srcs),
                         "packets": int(pkts)}
        if ips:
            src_ips.extend(ips.split(","))
        fs = f if not fs else min(fs, f)
        ls = l if not ls else max(ls, l)
    return [_finding(
        pattern_id="routing_proto_on_public_ip",
        pattern_title="Routing-protocol packets arriving on a public-facing IP",
        severity="high",
        category="infrastructure-anomaly",
        src_ips=src_ips,
        key_metrics=metrics,
        evidence_refs=[{"section": "25", "label": "nonipproto proto-num rows"}],
        report_anchor="#25-non-tcpudpicmp-ipv4-traffic-nonipproto",
        first_seen=fs, last_seen=ls,
    )]


def pat_ipsec_probe_from_scanner(con) -> list[dict]:
    """ESP/AH arrivals from sources that are also classified scanners."""
    if not _have(con, "nonip_per_ip"):
        return []
    have_scan = _have(con, "scannerintel")
    rows = con.execute("""
        SELECT n.src_ip, n.proto_num, n.packets,
               n.first_seen, n.last_seen
        FROM nonip_per_ip n
        WHERE n.proto_num IN (50, 51)
    """).fetchall()
    if not rows:
        return []
    ips = [r[0] for r in rows]
    in_clause = ("('" + ips[0] + "')" if len(ips) == 1 else str(tuple(ips)))
    metrics_per_ip: dict[str, dict] = {}
    asns: list[str] = []
    countries: list[str] = []
    if have_scan:
        scan_rows = con.execute(
            f"SELECT src_ip, port_count, pkt_count, country_iso, asn_org, l7_dominant "
            f"FROM scannerintel WHERE src_ip IN {in_clause}"
        ).fetchall()
        for sip, pc, pk, cc, asn, l7 in scan_rows:
            metrics_per_ip[sip] = {"port_count": int(pc),
                                   "scanner_pkts": int(pk),
                                   "l7_dominant": l7 or ""}
            if asn:
                asns.append(asn)
            if cc:
                countries.append(cc)
    return [_finding(
        pattern_id="ipsec_probe_from_scanner",
        pattern_title="IPsec (ESP/AH) packets arriving from active scanners",
        severity="medium",
        category="vpn-recon",
        src_ips=ips,
        asns=list(dict.fromkeys(asns)),
        countries=list(dict.fromkeys(countries)),
        key_metrics={
            "esp_packets": sum(int(r[2]) for r in rows if r[1] == 50),
            "ah_packets":  sum(int(r[2]) for r in rows if r[1] == 51),
            "scanner_overlap": len(metrics_per_ip),
            "per_ip": metrics_per_ip,
        },
        evidence_refs=[{"section": "25", "label": "nonipproto ESP/AH rows"}],
        report_anchor="#25-non-tcpudpicmp-ipv4-traffic-nonipproto",
        first_seen=min((r[3] for r in rows), default=""),
        last_seen=max((r[4] for r in rows), default=""),
    )]


def pat_covert_tunnel_setup(con) -> list[dict]:
    """IP-in-IP (4), 6to4 (41), GRE (47), ETHERIP (97) from active scanners."""
    if not _have(con, "nonip_per_ip"):
        return []
    rows = con.execute("""
        SELECT proto_num, proto_name,
               count(DISTINCT src_ip) AS srcs,
               sum(packets) AS pkts,
               min(first_seen) AS fs, max(last_seen) AS ls
        FROM nonip_per_ip
        WHERE proto_num IN (4, 41, 47, 97)
        GROUP BY proto_num, proto_name
        ORDER BY pkts DESC
    """).fetchall()
    if not rows:
        return []
    sample_ips = [r[0] for r in con.execute("""
        SELECT DISTINCT src_ip FROM nonip_per_ip
        WHERE proto_num IN (4, 41, 47, 97)
        ORDER BY src_ip LIMIT 25
    """).fetchall()]
    return [_finding(
        pattern_id="covert_tunnel_setup",
        pattern_title="Non-standard tunneling protocols arriving at the honeypot",
        severity="medium",
        category="evasion",
        src_ips=sample_ips,
        key_metrics={r[1]: {"distinct_srcs": int(r[2]), "packets": int(r[3])} for r in rows},
        evidence_refs=[{"section": "25", "label": "nonipproto IP-in-IP/6to4/GRE/ETHERIP rows"}],
        report_anchor="#25-non-tcpudpicmp-ipv4-traffic-nonipproto",
        first_seen=min((r[4] for r in rows), default=""),
        last_seen=max((r[5] for r in rows), default=""),
    )]


def pat_multi_transport_bulletproof(con) -> list[dict]:
    """Sources mixing TCP+UDP+ICMP payloads from bulletproof / hostile ASNs."""
    if not _have(con, "cross_proto"):
        return []
    bp_clause = ""
    if _have(con, "asnintel"):
        bp_clause = (
            "JOIN (SELECT DISTINCT asn FROM asnintel "
            "      WHERE bulletproof_flag = TRUE) bp "
            "  ON s.asn = bp.asn "
        )
    join_scan = ""
    if _have(con, "scannerintel"):
        join_scan = "LEFT JOIN scannerintel s ON s.src_ip = c.src_ip "
    have_features = bp_clause and join_scan
    if not have_features:
        rows = con.execute("""
            SELECT src_ip, payload_tcp, payload_udp, payload_icmp, multi_proto_score
            FROM cross_proto
            WHERE multi_proto_score >= 3
              AND payload_tcp > 0 AND payload_udp > 0
              AND payload_icmp > 0
            ORDER BY payload_tcp DESC LIMIT 50
        """).fetchall()
        if not rows:
            return []
        return [_finding(
            pattern_id="multi_transport_toolkit",
            pattern_title="Sources actively probing on TCP, UDP, and ICMP simultaneously",
            severity="medium",
            category="tooling-fingerprint",
            src_ips=[r[0] for r in rows],
            key_metrics={"matched_ips": len(rows), "top": [
                {"src_ip": r[0], "tcp": int(r[1]),
                 "udp": int(r[2]), "icmp": int(r[3])}
                for r in rows[:15]
            ]},
            evidence_refs=[{"section": "23",
                            "label": "protocolanomaly cross-protocol senders"}],
            report_anchor="#23-protocol-state-machine--cross-protocol-anomalies-protocolanomaly",
        )]
    rows = con.execute(f"""
        SELECT c.src_ip, c.payload_tcp, c.payload_udp, c.payload_icmp,
               s.asn, s.asn_org, s.country_iso, s.port_count
        FROM cross_proto c
        {join_scan}
        {bp_clause}
        WHERE c.multi_proto_score >= 3
          AND c.payload_tcp > 0 AND c.payload_udp > 0
          AND c.payload_icmp > 0
        ORDER BY c.payload_tcp DESC LIMIT 50
    """).fetchall()
    if not rows:
        return []
    return [_finding(
        pattern_id="multi_transport_bulletproof",
        pattern_title="Multi-transport toolkit traffic from bulletproof-hosting ASNs",
        severity="high",
        category="tooling-fingerprint",
        src_ips=[r[0] for r in rows],
        asns=list({r[5] for r in rows if r[5]}),
        countries=list({r[6] for r in rows if r[6]}),
        key_metrics={"matched_ips": len(rows), "top": [
            {"src_ip": r[0], "tcp": int(r[1]), "udp": int(r[2]), "icmp": int(r[3]),
             "asn_org": r[5], "country": r[6], "port_count": int(r[7] or 0)}
            for r in rows[:15]
        ]},
        evidence_refs=[
            {"section": "23", "label": "Cross-protocol senders"},
            {"section": "14", "label": "Hostile ASN profile"},
        ],
        report_anchor="#23-protocol-state-machine--cross-protocol-anomalies-protocolanomaly",
    )]


def pat_botnet_in_coordination_wave(con) -> list[dict]:
    """Mozi/Mirai sources participating in payload-synchronized waves."""
    risk_path = _newest_risk_path()
    if not risk_path or not _have(con, "waves"):
        return []
    bot_rows = con.execute(f"""
        SELECT src_ip, risk_score, rationale
        FROM read_parquet('{risk_path.as_posix()}')
        WHERE rationale ILIKE '%botnet=%'
    """).fetchall()
    if not bot_rows:
        return []
    bot_set = {r[0] for r in bot_rows}
    wave_rows = con.execute("""
        SELECT ip_count, first_seen, last_seen, l7_proto, sample_ips
        FROM waves
        ORDER BY ip_count DESC
        LIMIT 100
    """).fetchall()
    overlap_ips: set[str] = set()
    wave_hits: list[dict] = []
    for ic, _fs, _ls, l7, sample_ips in wave_rows:
        ips = [s.strip() for s in (sample_ips or "").split(",") if s.strip()]
        hit = [ip for ip in ips if ip in bot_set]
        if hit:
            overlap_ips.update(hit)
            wave_hits.append({
                "ip_count": int(ic), "l7_proto": l7 or "",
                "botnet_overlap": len(hit), "sample_ips": hit[:8],
            })
    if not overlap_ips:
        return []
    return [_finding(
        pattern_id="botnet_in_coordination_wave",
        pattern_title="Confirmed botnet sources participating in payload-synchronized waves",
        severity="critical",
        category="active-botnet",
        src_ips=list(overlap_ips),
        key_metrics={
            "overlap_ips":  len(overlap_ips),
            "waves_with_botnet_members": len(wave_hits),
            "top_waves": wave_hits[:8],
        },
        evidence_refs=[
            {"section": "6", "label": "Coordinated activity / payload waves"},
            {"section": "1", "label": "Risk tiers (botnet-rationale IPs)"},
        ],
        report_anchor="#6-coordinated-activity",
    )]


def pat_bulletproof_high_density(con) -> list[dict]:
    if not _have(con, "asnintel"):
        return []
    rows = con.execute("""
        SELECT asn, asn_org, country_iso, ip_count, threat_ip_count,
               threat_density, pkt_total, top_ports, top_botnet_fams,
               cooperation_score, risk_grade, block_recommend
        FROM asnintel
        WHERE bulletproof_flag = TRUE
          AND threat_density > 0.5
          AND ip_count >= 50
        ORDER BY threat_density DESC, ip_count DESC LIMIT 20
    """).fetchall()
    if not rows:
        return []
    return [_finding(
        pattern_id="bulletproof_high_density_asns",
        pattern_title="Bulletproof / abuse-tolerant ASNs with overwhelming threat density",
        severity="high",
        category="infrastructure-block",
        src_ips=[],
        asns=[f"AS{r[0]} {r[1]} ({r[2]})" for r in rows],
        countries=list({r[2] for r in rows if r[2]}),
        key_metrics={"asns": [
            {"asn": int(r[0]), "asn_org": r[1], "country": r[2],
             "ip_count": int(r[3]), "threat_ip_count": int(r[4]),
             "threat_density": round(float(r[5]), 3),
             "top_ports": r[7], "top_botnet_fams": r[8],
             "risk_grade": r[10], "block_recommend": r[11]}
            for r in rows
        ]},
        evidence_refs=[{"section": "14", "label": "Hostile ASN profile"}],
        report_anchor="#14-hostile-asns---per-network-threat-profile-asnintel",
    )]


def pat_rdp_credential_spray(con) -> list[dict]:
    """One mstshash cookie reused across many source IPs."""
    if not _have(con, "rdpbrute"):
        return []
    rows = con.execute("""
        SELECT mstshash, src_ip_count, hit_count,
               first_seen, last_seen, day_count, sample_srcs
        FROM rdpbrute
        WHERE src_ip_count >= 25
        ORDER BY src_ip_count DESC LIMIT 25
    """).fetchall()
    if not rows:
        return []
    samples: list[str] = []
    for _, _, _, _, _, _, ss in rows:
        if ss:
            samples.extend(s.strip() for s in ss.split(",")[:5])
    return [_finding(
        pattern_id="rdp_credential_spray",
        pattern_title="RDP credential spray - one cookie reused across many sources",
        severity="high",
        category="credential-attack",
        src_ips=samples,
        key_metrics={"top": [
            {"mstshash": r[0], "src_ip_count": int(r[1]),
             "hit_count": int(r[2]), "day_count": int(r[5]),
             "first": str(r[3]), "last": str(r[4])}
            for r in rows[:10]
        ]},
        evidence_refs=[{"section": "8", "label": "Botnet / malware activity + RDP brute"}],
        report_anchor="#8-botnet--malware-activity",
    )]


def pat_low_slow_subnet_coordinated(con) -> list[dict]:
    """Long-span low-density scanners with multiple subnet members."""
    if not _have(con, "slowlow"):
        return []
    rows = con.execute("""
        SELECT src_ip, span_days, active_days, density, subnet24,
               subnet_members, asn_org, country_iso
        FROM slowlow
        WHERE span_days >= 90 AND density < 0.1 AND subnet_members >= 3
        ORDER BY subnet_members DESC, span_days DESC LIMIT 40
    """).fetchall()
    if not rows:
        return []
    return [_finding(
        pattern_id="low_slow_subnet_coordinated",
        pattern_title="Coordinated low-and-slow scanning across multiple subnet members",
        severity="medium",
        category="stealth-recon",
        src_ips=[r[0] for r in rows],
        asns=list({r[6] for r in rows if r[6]}),
        countries=list({r[7] for r in rows if r[7]}),
        key_metrics={"top": [
            {"src_ip": r[0], "span_days": int(r[1]), "active_days": int(r[2]),
             "density": round(float(r[3]), 3), "subnet24": r[4],
             "subnet_members": int(r[5]), "asn_org": r[6], "country": r[7]}
            for r in rows[:15]
        ]},
        evidence_refs=[{"section": "11", "label": "Temporal patterns / slowlow"}],
        report_anchor="#11-temporal-patterns",
    )]


def pat_wrong_proto_amp_endpoints(con) -> list[dict]:
    """TCP probes to known UDP-amp ports (DNS, NTP, SSDP, mDNS, SNMP)."""
    if not _have(con, "wrong_proto_port"):
        return []
    rows = con.execute("""
        SELECT proto, dst_port, packets, ips, note
        FROM wrong_proto_port
        WHERE (proto = 'TCP' AND dst_port IN (53, 123, 161, 1900, 5353))
           OR (proto = 'UDP' AND dst_port IN (22, 23, 80, 443, 3389))
        ORDER BY ips DESC
    """).fetchall()
    if not rows:
        return []
    return [_finding(
        pattern_id="wrong_proto_for_port",
        pattern_title="Wrong-transport probes against well-known service ports",
        severity="medium",
        category="amp-recon",
        src_ips=[],
        key_metrics={"rows": [
            {"proto": r[0], "dst_port": int(r[1]), "packets": int(r[2]),
             "ips": int(r[3]), "note": r[4]}
            for r in rows
        ]},
        evidence_refs=[{"section": "23", "label": "Wrong-proto-for-port table"}],
        report_anchor="#23-protocol-state-machine--cross-protocol-anomalies-protocolanomaly",
    )]


def pat_icmp_payload_anomalies(con) -> list[dict]:
    if not _have(con, "icmp_payload"):
        return []
    rows = con.execute(
        "SELECT anomaly_kind, packets, distinct_ips FROM icmp_payload"
    ).fetchall()
    if not rows:
        return []
    total_pkts = sum(int(r[1]) for r in rows)
    total_ips = sum(int(r[2]) for r in rows)
    if total_pkts < 100:
        return []
    return [_finding(
        pattern_id="icmp_payload_anomalies",
        pattern_title="ICMP packets carrying non-trivial payload - covert channel candidate",
        severity="medium",
        category="covert-channel",
        src_ips=[],
        key_metrics={"breakdown": [
            {"kind": r[0], "packets": int(r[1]), "ips": int(r[2])} for r in rows
        ], "total_packets": total_pkts, "total_ips": total_ips},
        evidence_refs=[{"section": "23", "label": "ICMP-payload anomalies"}],
        report_anchor="#23-protocol-state-machine--cross-protocol-anomalies-protocolanomaly",
    )]


def pat_tcp_midstream_spoof(con) -> list[dict]:
    if not _have(con, "tcp_state"):
        return []
    rows = con.execute("""
        SELECT anomaly_kind, packets, distinct_ips
        FROM tcp_state
        WHERE anomaly_kind ILIKE '%mid-stream%'
           OR anomaly_kind ILIKE '%SYN with payload%'
    """).fetchall()
    if not rows:
        return []
    if max(int(r[1]) for r in rows) < 100:
        return []
    return [_finding(
        pattern_id="tcp_midstream_or_syn_payload",
        pattern_title="TCP state-machine violations - spoofing or raw-socket scanners",
        severity="medium",
        category="protocol-violation",
        src_ips=[],
        key_metrics={"breakdown": [
            {"kind": r[0], "packets": int(r[1]), "ips": int(r[2])} for r in rows
        ]},
        evidence_refs=[{"section": "23", "label": "TCP state-machine anomalies"}],
        report_anchor="#23-protocol-state-machine--cross-protocol-anomalies-protocolanomaly",
    )]


def pat_global_arrival_burst(con) -> list[dict]:
    if not _have(con, "bursts"):
        return []
    rows = con.execute("""
        SELECT bucket_start, new_ip_count, baseline, ratio
        FROM bursts
        WHERE ratio >= 5.0
        ORDER BY ratio DESC LIMIT 15
    """).fetchall()
    if not rows:
        return []
    return [_finding(
        pattern_id="global_arrival_burst",
        pattern_title="Coordinated arrival bursts - sudden floods of brand-new sources",
        severity="high",
        category="botnet-rotation",
        src_ips=[],
        key_metrics={"top": [
            {"bucket_start": str(r[0]), "new_ip_count": int(r[1]),
             "baseline": float(r[2]), "ratio": float(r[3])}
            for r in rows
        ]},
        evidence_refs=[{"section": "6", "label": "Arrival bursts"}],
        report_anchor="#6-coordinated-activity",
        first_seen=str(rows[-1][0]), last_seen=str(rows[0][0]),
    )]


def pat_local_only_vnc_targeting(con) -> list[dict]:
    """ISC-comparison local-only ports - VNC family + Mikrotik RouterOS."""
    if not _have(con, "isc_compare"):
        return []
    rows = con.execute("""
        SELECT port, local_packets, local_ips
        FROM isc_compare
        WHERE port BETWEEN 5900 AND 5910
           OR port IN (8728, 8729, 34567, 47662)
        ORDER BY local_packets DESC
    """).fetchall()
    if not rows:
        return []
    return [_finding(
        pattern_id="local_only_targeted_ports",
        pattern_title="Targeted ports the sensor sees but the global ISC feed does not",
        severity="high",
        category="targeting",
        src_ips=[],
        key_metrics={"rows": [
            {"port": int(r[0]), "packets": int(r[1]), "ips": int(r[2])}
            for r in rows
        ]},
        evidence_refs=[{"section": "24", "label": "SANS ISC comparison local-only ports"}],
        report_anchor="#24-sans-isc-comparison-isc_compare",
    )]


def pat_self_mimic_honeypot_aware(con) -> list[dict]:
    if not _have(con, "selfmimic"):
        return []
    rows = con.execute("""
        SELECT src_ip, echo_count, banner_hits, mimic_score,
               first_seen, last_seen, country_iso, asn_org
        FROM selfmimic
        WHERE mimic_score >= 0.5
        ORDER BY mimic_score DESC, echo_count DESC LIMIT 25
    """).fetchall()
    if not rows:
        return []
    return [_finding(
        pattern_id="honeypot_aware_self_mimic",
        pattern_title="Sources echoing the sensor's own banners back - honeypot-aware",
        severity="high",
        category="evasion",
        src_ips=[r[0] for r in rows],
        asns=list({r[7] for r in rows if r[7]}),
        countries=list({r[6] for r in rows if r[6]}),
        key_metrics={"top": [
            {"src_ip": r[0], "echo_count": int(r[1]),
             "banner_hits": r[2], "mimic_score": float(r[3])}
            for r in rows[:10]
        ]},
        evidence_refs=[{"section": "selfmimic", "label": "selfmimic analyzer"}],
        report_anchor="#22-threat-landscape-evolution-landscape",
    )]


def pat_critical_persistent_botnet(con) -> list[dict]:
    """Critical-tier IPs with botnet rationale AND long persistence."""
    risk_path = _newest_risk_path()
    if not risk_path:
        return []
    rows = con.execute(f"""
        SELECT src_ip, risk_score, persistence, botnet_signal, rationale
        FROM read_parquet('{risk_path.as_posix()}')
        WHERE risk_tier = 'critical'
          AND botnet_signal > 0.5
          AND persistence > 0.6
        ORDER BY risk_score DESC LIMIT 50
    """).fetchall()
    if not rows:
        return []
    return [_finding(
        pattern_id="critical_persistent_botnet",
        pattern_title="Critical-tier botnet sources with long-running persistence",
        severity="critical",
        category="active-botnet",
        src_ips=[r[0] for r in rows],
        key_metrics={"matched": len(rows), "top": [
            {"src_ip": r[0], "risk": round(float(r[1]), 1),
             "persistence": round(float(r[2]), 3),
             "rationale": r[4]} for r in rows[:15]
        ]},
        evidence_refs=[{"section": "1", "label": "Risk tier critical"}],
        report_anchor="#1-executive-summary",
    )]


PATTERNS: list[Callable] = [
    pat_telco_ss7_recon,
    pat_routing_protocol_on_public_ip,
    pat_ipsec_probe_from_scanner,
    pat_covert_tunnel_setup,
    pat_multi_transport_bulletproof,
    pat_botnet_in_coordination_wave,
    pat_bulletproof_high_density,
    pat_rdp_credential_spray,
    pat_low_slow_subnet_coordinated,
    pat_wrong_proto_amp_endpoints,
    pat_icmp_payload_anomalies,
    pat_tcp_midstream_spoof,
    pat_global_arrival_burst,
    pat_local_only_vnc_targeting,
    pat_self_mimic_honeypot_aware,
    pat_critical_persistent_botnet,
]


_REGISTERED: set[str] = set()


def _have(con, view: str) -> bool:
    return view in _REGISTERED


def _register_views(con) -> None:
    R = lib.REPORTS
    P = lib.OUTPUT_DIR / "patterns"
    mapping: list[tuple[str, Path]] = [
        ("portscans",        R / "portscans" / "portscans.parquet"),
        ("scannerintel",     R / "scannerintel" / "scannerintel.parquet"),
        ("rdpbrute",         R / "rdpbrute"   / "rdpbrute.parquet"),
        ("nonip_per_ip",     R / "nonipproto" / "per_ip.parquet"),
        ("nonip_agg",        R / "nonipproto" / "nonipproto.parquet"),
        ("cross_proto",      R / "protocolanomaly" / "cross_proto.parquet"),
        ("wrong_proto_port", R / "protocolanomaly" / "wrong_proto_port.parquet"),
        ("tcp_state",        R / "protocolanomaly" / "tcp_state.parquet"),
        ("icmp_payload",     R / "protocolanomaly" / "icmp_payload.parquet"),
        ("asnintel",         R / "asnintel"  / "asnintel.parquet"),
        ("cidrintel",        R / "cidrintel" / "cidrintel.parquet"),
        ("tooling",          R / "tooling"   / "tooling.parquet"),
        ("slowlow",          R / "slowlow"   / "slowlow.parquet"),
        ("selfmimic",        R / "selfmimic" / "selfmimic.parquet"),
        ("isc_compare",      R / "isc_compare" / "isc_compare.parquet"),
        ("ai_decode",        R / "ai_decode" / "decodes.parquet"),
        ("waves",            P / "coordination" / "payload_waves.parquet"),
        ("bursts",           P / "coordination" / "arrival_bursts.parquet"),
        ("chains",           P / "attack_chains" / "patterns.parquet"),
    ]
    for view, path in mapping:
        if _table(con, path, view):
            _REGISTERED.add(view)

    try:
        lib.register_views(con)
        con.execute("SELECT 1 FROM packets LIMIT 1").fetchone()
        con.execute("CREATE OR REPLACE VIEW pkt_view AS SELECT * FROM packets")
        _REGISTERED.add("pkt_view")
    except Exception:
        pass


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    con = lib.duck(memory_limit="8GB")
    _register_views(con)
    print(f"[correlate] registered views: {sorted(_REGISTERED)}", file=sys.stderr)

    findings: list[dict] = []
    for fn in PATTERNS:
        try:
            res = fn(con) or []
        except Exception as e:
            print(f"[correlate] pattern {fn.__name__} failed: {e}", file=sys.stderr)
            continue
        for r in res:
            findings.append(r)
        print(f"[correlate] {fn.__name__}: {len(res)} finding(s)", file=sys.stderr)

    pq.write_table(
        pa.Table.from_pylist(findings, schema=FINDING_SCHEMA),
        OUT_DIR / "findings.parquet",
        compression="zstd", compression_level=3,
    )

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings_sorted = sorted(findings, key=lambda f: sev_order.get(f["severity"], 9))
    md = ["# conclusions/correlate - cross-analyzer findings index", "",
          f"_{len(findings)} finding(s) detected by {len(PATTERNS)} cross-analyzer rules._",
          "",
          "Each row points to one cross-signal pattern.  The narrative",
          "conclusions (what / why / threat-model / risk / action) are",
          "written by `conclusions/synthesize.py` into `conclusions.md`.",
          "",
          "| severity | pattern_id | title | src_ips | category |",
          "| --- | --- | --- | --- | --- |"]
    for f in findings_sorted:
        md.append(
            f"| {f['severity']} | `{f['pattern_id']}` | "
            f"{f['pattern_title']} | {f['src_ip_count']} | {f['category']} |"
        )
    (OUT_DIR / "findings.md").write_text("\n".join(md) + "\n")

    print(f"[correlate] wrote {len(findings)} findings to {OUT_DIR/'findings.parquet'}",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

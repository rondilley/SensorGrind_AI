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
#   2123/2152 = GTP-C/-U (GPRS), 2905 = M3UA (SS7),
#   2944/2945 = MEGACO/H.248, 3868 = Diameter, 5060/5061 = SIP/SIPS,
#   5868 = Diameter-DTLS, 36412 = S1AP (LTE eNodeB-MME),
#   36422 = X2AP (inter-eNodeB), 36443/36444 = M2AP/M3AP.
TELCO_TCP_PORTS: frozenset[int] = frozenset({
    2123, 2152, 2905, 2944, 2945, 3868, 5060, 5061, 5868,
    36412, 36422, 36443, 36444,
})


# ----------------------------------------------------------------------
# Pattern thresholds (centralized so they can be tuned in one place
# rather than buried as inline magic numbers across 18 rule functions).
# ----------------------------------------------------------------------
MIN_BULLETPROOF_DENSITY     = 0.50   # asnintel threat_density cutoff
MIN_BULLETPROOF_IP_COUNT    = 50
MIN_RDP_SPRAY_IPS           = 25
MIN_SELFMIMIC_SCORE         = 0.50
MIN_RECENT_CAMPAIGN_IPS     = 500
MAX_RECENT_CAMPAIGN_BURST_D = 7
RECENT_CAMPAIGN_WINDOW_D    = 60
MIN_SYNC_BURST_CAMPAIGNS    = 5
MIN_LOWSLOW_SPAN_DAYS       = 90
MAX_LOWSLOW_DENSITY         = 0.10
MIN_LOWSLOW_SUBNET_MEMBERS  = 3
MIN_ARRIVAL_BURST_RATIO     = 5.0
MIN_BOTNET_SIGNAL           = 0.5
MIN_BOTNET_PERSISTENCE      = 0.6

# chainfp thresholds — per ListonCon long-tail observation.  The
# "distinctive" tier is 10-99 source IPs sharing the same chain.
# Rare/singleton sit below.  At the high end, anything seen from
# >=1000 sources is internet-background and uninteresting.
CHAINFP_DISTINCTIVE_MIN     = 10
CHAINFP_DISTINCTIVE_MAX     = 99
CHAINFP_MIN_TOKENS          = 3      # 2-token "SYN+RST" is too short to be a fingerprint
CHAINFP_TOP_DISTINCTIVE     = 15     # finding fan-out cap
CHAINFP_TOP_RARE_BURST      = 8      # rare chains promoted by burstiness
# Timed-chain tempo: a distinctive chain whose sources nearly all share ONE
# timed variant (the same sequence AND the same per-source-normalized inter-
# token cadence) is a tight mechanical/tooling fingerprint.  Above this share
# of sources concentrating in the dominant tempo mode we flag it as such.
CHAINFP_MECHANICAL_TEMPO    = 0.80

# compositeprint rotation thresholds (Phase 3).  A behavioral fingerprint
# (core_hash) fuses stack+sequence+tempo+app+payload and is independent of
# infrastructure, so the SAME core_hash seen from many ASNs/CIDRs is one
# tool/campaign deployed across rotated hosting.  We surface the ones spread
# widely enough to matter, drop generic ping sweeps, and promote on either a
# wide spread or a dormancy-then-return with the infrastructure changed.
COMPOSITE_MIN_ASNS          = 3      # spans >= 3 ASNs to count as "distributed"
COMPOSITE_HIGH_ASNS         = 8      # wide spread -> high severity
COMPOSITE_TOP_ROTATION      = 25     # finding fan-out cap
COMPOSITE_REEMERGE_GAP_H    = 6.0    # dormancy gap (hours) that counts as a return

# Bulletproof ASN cluster: connected groups in the campaignmigration
# ISP-collaboration graph (ASNs sharing the same migrating campaign
# fingerprints) that also carry asnintel bulletproof / coordination signals.
BP_CLUSTER_MIN_EDGE         = 3      # cohost edge weight (shared campaigns) to link two ASNs
BP_CLUSTER_MIN_ASNS         = 3      # min ASNs in a cluster to report
BP_CLUSTER_COOP_HIGH        = 0.5    # mean asnintel cooperation_score -> coordinated
BP_CLUSTER_TOP              = 20     # finding fan-out cap


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

    telco_ports_list = sorted(TELCO_TCP_PORTS)
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
    rows = con.execute(f"""
        SELECT asn, asn_org, country_iso, ip_count, threat_ip_count,
               threat_density, pkt_total, top_ports, top_botnet_fams,
               cooperation_score, risk_grade, block_recommend
        FROM asnintel
        WHERE bulletproof_flag = TRUE
          AND threat_density > {MIN_BULLETPROOF_DENSITY}
          AND ip_count >= {MIN_BULLETPROOF_IP_COUNT}
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
    rows = con.execute(f"""
        SELECT mstshash, src_ip_count, hit_count,
               first_seen, last_seen, day_count, sample_srcs
        FROM rdpbrute
        WHERE src_ip_count >= {MIN_RDP_SPRAY_IPS}
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
    rows = con.execute(f"""
        SELECT src_ip, span_days, active_days, density, subnet24,
               subnet_members, asn_org, country_iso
        FROM slowlow
        WHERE span_days >= {MIN_LOWSLOW_SPAN_DAYS}
          AND density < {MAX_LOWSLOW_DENSITY}
          AND subnet_members >= {MIN_LOWSLOW_SUBNET_MEMBERS}
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
    rows = con.execute(f"""
        SELECT bucket_start, new_ip_count, baseline, ratio
        FROM bursts
        WHERE ratio >= {MIN_ARRIVAL_BURST_RATIO}
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
    rows = con.execute(f"""
        SELECT src_ip, echo_count, banner_hits, mimic_score,
               first_seen, last_seen, country_iso, asn_org
        FROM selfmimic
        WHERE mimic_score >= {MIN_SELFMIMIC_SCORE}
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


def pat_synchronized_campaign_burst(con) -> list[dict]:
    """N+ distinct payloads sharing the same peak day - coordinated push."""
    if not _have(con, "waves"):
        return []
    rows = con.execute(f"""
        SELECT date_trunc('day', peak_day) AS d,
               count(*)                    AS campaign_count,
               sum(ip_count)               AS total_ips,
               sum(peak_count)             AS total_peak_day_ips,
               list(l7_proto)              AS l7s,
               list(ip_count ORDER BY ip_count DESC)[:5] AS top_ip_counts,
               list(sample_ips)            AS all_samples
        FROM waves
        WHERE is_campaign = TRUE
          AND peak_day IS NOT NULL
        GROUP BY d
        HAVING count(*) >= {MIN_SYNC_BURST_CAMPAIGNS}
        ORDER BY campaign_count DESC, total_ips DESC
        LIMIT 10
    """).fetchall()
    if not rows:
        return []
    out: list[dict] = []
    for d, n_camps, total_ips, peak_ips, l7s, top_counts, all_samples in rows:
        ips: list[str] = []
        for s in (all_samples or []):
            if s:
                ips.extend(p.strip() for p in s.split(",") if p.strip())
        seen: set[str] = set()
        uniq_ips = [ip for ip in ips if not (ip in seen or seen.add(ip))]
        l7_counter: dict[str, int] = {}
        for p in (l7s or []):
            if p:
                l7_counter[p] = l7_counter.get(p, 0) + 1
        out.append(_finding(
            pattern_id="synchronized_campaign_burst",
            pattern_title=(
                f"Synchronized push: {int(n_camps)} distinct payloads "
                f"peaked together on {d.date().isoformat() if hasattr(d,'date') else str(d)[:10]}"
            ),
            severity="critical",
            category="coordinated-push",
            src_ips=uniq_ips[:25],
            key_metrics={
                "peak_day":                str(d)[:10],
                "distinct_campaigns":      int(n_camps),
                "total_ips_across_camps":  int(total_ips),
                "total_peak_day_ips":      int(peak_ips),
                "top_campaign_ip_counts":  [int(x) for x in (top_counts or [])],
                "l7_breakdown":            l7_counter,
            },
            evidence_refs=[
                {"section": "6", "label": "Top 50 campaigns table - rows sharing this peak_day"},
                {"section": "6", "label": "Top 20 campaign Gantt"},
            ],
            report_anchor="#6-coordinated-activity---campaign-onsets--arrival-bursts",
            first_seen=str(d)[:10],
            last_seen=str(d)[:10],
        ))
    return out


def pat_recent_tight_campaign(con) -> list[dict]:
    """Campaigns launched recently with tight burst windows + large operator counts."""
    if not _have(con, "waves"):
        return []
    corpus_max = con.execute(
        "SELECT max(last_seen) FROM waves WHERE is_campaign = TRUE"
    ).fetchone()[0]
    if corpus_max is None:
        return []
    rows = con.execute(f"""
        SELECT payload_sha256, l7_proto, ip_count, peak_count,
               launch_ts, peak_day, decay_ts,
               burst_window_days, density_score, sample_ips
        FROM waves
        WHERE is_campaign = TRUE
          AND launch_ts >= TIMESTAMP '{corpus_max}'
                          - INTERVAL '{RECENT_CAMPAIGN_WINDOW_D} days'
          AND burst_window_days < {MAX_RECENT_CAMPAIGN_BURST_D}
          AND ip_count >= {MIN_RECENT_CAMPAIGN_IPS}
        ORDER BY density_score DESC
        LIMIT 25
    """).fetchall()
    if not rows:
        return []
    sample_ips: list[str] = []
    for r in rows:
        s = r[9]
        if s:
            for ip in s.split(","):
                ip = ip.strip()
                if ip and ip not in sample_ips:
                    sample_ips.append(ip)
                    if len(sample_ips) >= 25:
                        break
        if len(sample_ips) >= 25:
            break
    return [_finding(
        pattern_id="recent_tight_campaign",
        pattern_title=(
            f"{len(rows)} fresh tight campaigns launched in the last 60 days "
            "(burst < 7d, >=500 IPs each)"
        ),
        severity="high",
        category="campaign-onset",
        src_ips=sample_ips,
        key_metrics={
            "campaign_count":  len(rows),
            "window":          f"{corpus_max} minus 60d -> {corpus_max}",
            "top": [
                {
                    "l7":         r[1] or "unknown",
                    "ip_count":   int(r[2]),
                    "peak_count": int(r[3] or 0),
                    "launch_ts":  str(r[4])[:19],
                    "peak_day":   str(r[5])[:10],
                    "decay_ts":   str(r[6])[:19],
                    "burst_days": round(float(r[7]), 2),
                    "density":    round(float(r[8]), 0),
                }
                for r in rows[:10]
            ],
        },
        evidence_refs=[
            {"section": "6", "label": "Top 50 campaigns table (sorted by density_score)"},
            {"section": "6", "label": "Campaign launches per month"},
        ],
        report_anchor="#6-coordinated-activity---campaign-onsets--arrival-bursts",
    )]


def _timed_tempo_map(con, untimed_chains: list[str]) -> dict[str, dict]:
    """Map each untimed chain to its timed-chain tempo decomposition.

    `chainfp_timed` holds the SAME proto/port choreography as `chainfp`,
    but with a `~<tempo>` tag appended to every token (the token's inter-
    arrival gap bucketed against that source's own baseline cadence).
    Stripping `~[s0-3]` from a timed chain recovers its untimed form,
    which is how the two tables join.

    For each requested untimed chain we return:
      - dominant_timed_chain: the most common timed variant
      - tempo_coherence:      share of that chain's sources whose timing
                              collapses into that single dominant variant
      - tempo_modes:          how many distinct timed variants it splits into

    A high coherence with few modes means the sources don't just send the
    same packets in the same order, they send them on the same clock -- a
    mechanical/tooling tell that pure sequence can't see.  Long chains may
    truncate at a different token boundary than their untimed twin (the
    `~X` tags add width), in which case the join misses and the chain is
    simply returned without tempo enrichment.
    """
    if not _have(con, "chainfp_timed") or not untimed_chains:
        return {}
    targets = sorted(set(untimed_chains))
    con.execute("CREATE OR REPLACE TEMP TABLE _tgt_chains(chain VARCHAR)")
    con.executemany("INSERT INTO _tgt_chains VALUES (?)",
                    [(c,) for c in targets])
    rows = con.execute("""
        WITH mapped AS (
            SELECT regexp_replace(chain, '~[s0-3]', '', 'g') AS base_chain,
                   chain AS timed_chain,
                   source_count
            FROM chainfp_timed
        ),
        joined AS (
            SELECT m.base_chain, m.timed_chain, m.source_count
            FROM mapped m
            SEMI JOIN _tgt_chains t ON m.base_chain = t.chain
        ),
        ranked AS (
            SELECT base_chain, timed_chain, source_count,
                   sum(source_count) OVER (PARTITION BY base_chain) AS tot,
                   count(*)          OVER (PARTITION BY base_chain) AS n_modes,
                   row_number()      OVER (PARTITION BY base_chain
                                           ORDER BY source_count DESC,
                                                    timed_chain ASC) AS rn
            FROM joined
        )
        SELECT base_chain, timed_chain, source_count, tot, n_modes
        FROM ranked WHERE rn = 1
    """).fetchall()
    out: dict[str, dict] = {}
    for base, timed, sc, tot, n_modes in rows:
        share = (float(sc) / float(tot)) if tot else 0.0
        out[base] = {
            "dominant_timed_chain": timed,
            "tempo_coherence":      round(share, 3),
            "tempo_modes":          int(n_modes),
        }
    return out


def pat_anomalous_chain(con) -> list[dict]:
    """Distinctive per-IP packet-flag chains (from chainfp).

    Chains are per-source-IP sequences of `(flag_mask, proto, port)`
    tokens within one session.  The 'distinctive' tier (10-99 sources
    sharing the same chain) is the most informative bucket: cohesive
    enough to be a toolkit fingerprint, rare enough not to be background
    scanning.

    This rule picks the highest-source-count distinctive chains
    on the best-SNR window and emits one finding per chain.  The
    LLM synth stage then narrates what the chain operationally
    means.

    The 'rare' bucket (2-9 sources) is *also* surfaced, but only
    when the per-IP packet count is high enough that the chain
    represents real volume (filtering out one-off probe noise).
    """
    if not _have(con, "chainfp"):
        return []
    # Pick the best-SNR window if window_snr is registered; otherwise
    # default to 40m (matches Liston's `-t 2400` from ListonCon).
    best_label = "40m"
    if _have(con, "chainfp_snr"):
        try:
            row = con.execute("""
                SELECT window_label FROM chainfp_snr
                WHERE is_best = TRUE LIMIT 1
            """).fetchone()
            if row:
                best_label = row[0]
        except Exception:
            pass

    out: list[dict] = []

    # Distinctive chains: cohesive small-cluster toolkit fingerprints.
    distinctive = con.execute(f"""
        SELECT chain, source_count, packet_count, token_count,
               sample_ips, top_dst_ports, first_seen, last_seen
        FROM chainfp
        WHERE window_label = '{best_label}'
          AND anomaly_tier = 'distinctive'
          AND source_count BETWEEN {CHAINFP_DISTINCTIVE_MIN}
                              AND {CHAINFP_DISTINCTIVE_MAX}
          AND token_count >= {CHAINFP_MIN_TOKENS}
          AND chain NOT LIKE 'ICMP/8.0,ICMP/8.0,ICMP/8.0%'
        ORDER BY source_count DESC, packet_count DESC
        LIMIT {CHAINFP_TOP_DISTINCTIVE}
    """).fetchall()
    tempo = _timed_tempo_map(con, [r[0] for r in distinctive])
    for chain, src_count, pkt_count, tok_count, ips, ports, ts0, ts1 in distinctive:
        ip_list = (ips or "").split(",")
        # Severity heuristic: chain length + which structural tells.
        # SYN-then-own-RST or RST-without-prior-SYN are stronger
        # tells than a clean 3-token handshake.
        sev = "medium"
        weird = []
        c = chain or ""
        if "S*-TCP" in c and ",***R**-TCP" in c:
            # SYN-then-own-RST: source kernel disowned its own SYN.
            # Spoofing tell or stack-fingerprint probe.
            sev = "high"
            weird.append("SYN-then-own-RST")
        if c.startswith("***R**-TCP"):
            # Chain starts with RST from source - no prior SYN.
            sev = "high"
            weird.append("RST-without-prior-SYN")
        if c.count(",") >= 6 and "*A***F-TCP" not in c and "*A*R**-TCP" not in c:
            # Long chain with no normal teardown - lingering tarpit
            # probing or banner-grabbing without closing.
            weird.append("no-teardown")
        if tok_count >= 8 and "ICMP" in c:
            # Long ICMP-laced chain - protocol confusion or mapping.
            weird.append("icmp-mixed")

        # Timed-chain enrichment: how tightly the sources sharing this
        # sequence also share a single cadence.  High coherence over a
        # multi-token chain is a mechanical/scripted-tooling tell -- the
        # sources move on the same clock, not just in the same order.
        tm = tempo.get(c)
        tempo_metrics: dict = {}
        if tm:
            tempo_metrics = {
                "tempo_coherence":      tm["tempo_coherence"],
                "tempo_modes":          tm["tempo_modes"],
                "dominant_tempo_chain": tm["dominant_timed_chain"][:512],
            }
            if (tok_count >= CHAINFP_MIN_TOKENS
                    and tm["tempo_coherence"] >= CHAINFP_MECHANICAL_TEMPO):
                weird.append("mechanical-tempo")

        out.append(_finding(
            pattern_id=f"anom_chain_{hashlib.sha256(c.encode()).hexdigest()[:8]}",
            pattern_title=(f"Anomalous packet-flag chain ({src_count} "
                           f"sources, {tok_count} tokens)"),
            severity=sev,
            category="choreography-anomaly",
            src_ips=ip_list,
            key_metrics={
                "chain":         c[:512],
                "window":        best_label,
                "source_count":  int(src_count),
                "packet_count":  int(pkt_count),
                "token_count":   int(tok_count),
                "top_dst_ports": ports,
                "weird_tells":   weird,
                **tempo_metrics,
            },
            evidence_refs=[{"section": "chainfp",
                            "label": "Per-IP chain fingerprint"}],
            report_anchor="#chain-fingerprints-chainfp",
            first_seen=str(ts0), last_seen=str(ts1),
        ))

    # Rare-tier chains that nevertheless carry real packet volume.
    # These are tiny named-IP clusters running a sustained operation
    # rather than one-off probes.
    rare = con.execute(f"""
        SELECT chain, source_count, packet_count, token_count,
               sample_ips, top_dst_ports, first_seen, last_seen
        FROM chainfp
        WHERE window_label = '{best_label}'
          AND anomaly_tier = 'rare'
          AND token_count >= {CHAINFP_MIN_TOKENS}
          AND packet_count >= 200
          AND chain NOT LIKE 'ICMP/8.0%'
        ORDER BY packet_count DESC
        LIMIT {CHAINFP_TOP_RARE_BURST}
    """).fetchall()
    tempo_rare = _timed_tempo_map(con, [r[0] for r in rare])
    for chain, src_count, pkt_count, tok_count, ips, ports, ts0, ts1 in rare:
        ip_list = (ips or "").split(",")
        tm = tempo_rare.get(chain)
        tempo_metrics = {
            "tempo_coherence":      tm["tempo_coherence"],
            "tempo_modes":          tm["tempo_modes"],
            "dominant_tempo_chain": tm["dominant_timed_chain"][:512],
        } if tm else {}
        out.append(_finding(
            pattern_id=f"rare_chain_{hashlib.sha256(chain.encode()).hexdigest()[:8]}",
            pattern_title=(f"Rare sustained packet-flag chain "
                           f"({src_count} sources, {pkt_count:,} pkts)"),
            severity="medium",
            category="choreography-anomaly",
            src_ips=ip_list,
            key_metrics={
                "chain":         chain[:512],
                "window":        best_label,
                "source_count":  int(src_count),
                "packet_count":  int(pkt_count),
                "token_count":   int(tok_count),
                "top_dst_ports": ports,
                "is_rare":       True,
                **tempo_metrics,
            },
            evidence_refs=[{"section": "chainfp",
                            "label": "Per-IP chain fingerprint (rare tier)"}],
            report_anchor="#chain-fingerprints-chainfp",
            first_seen=str(ts0), last_seen=str(ts1),
        ))

    return out


def pat_critical_persistent_botnet(con) -> list[dict]:
    """Critical-tier IPs with botnet rationale AND long persistence."""
    risk_path = _newest_risk_path()
    if not risk_path:
        return []
    rows = con.execute(f"""
        SELECT src_ip, risk_score, persistence, botnet_signal, rationale
        FROM read_parquet('{risk_path.as_posix()}')
        WHERE risk_tier = 'critical'
          AND botnet_signal > {MIN_BOTNET_SIGNAL}
          AND persistence > {MIN_BOTNET_PERSISTENCE}
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


def _rotation_timeline(con, core_hashes: list[str]) -> dict[str, dict]:
    """Per core_hash, the dormancy structure of its episode timeline.

    Orders a fingerprint's episodes by time and measures the gaps between
    consecutive episodes.  A gap beyond COMPOSITE_REEMERGE_GAP_H means the
    behaviour went quiet and then RESUMED -- a campaign that paused and came
    back.  Combined with the cluster already spanning multiple ASNs/CIDRs, the
    return is on different infrastructure.  Returns {core_hash: {max_gap_h,
    n_dormancies, re_emergent}}.
    """
    if not _have(con, "composite_ep") or not core_hashes:
        return {}
    con.execute("CREATE OR REPLACE TEMP TABLE _rot_cores(core_hash VARCHAR)")
    con.executemany("INSERT INTO _rot_cores VALUES (?)",
                    [(h,) for h in sorted(set(core_hashes))])
    rows = con.execute(f"""
        WITH ep AS (
            SELECT e.core_hash, e.first_seen, e.last_seen
            FROM composite_ep e SEMI JOIN _rot_cores r ON e.core_hash = r.core_hash
        ),
        gaps AS (
            SELECT core_hash,
                   (epoch(first_seen) - epoch(lag(last_seen) OVER (
                        PARTITION BY core_hash ORDER BY first_seen, last_seen)))
                   / 3600.0 AS gap_h
            FROM ep
        )
        SELECT core_hash,
               coalesce(max(gap_h), 0.0) AS max_gap_h,
               count(*) FILTER (WHERE gap_h > {COMPOSITE_REEMERGE_GAP_H}) AS n_dormancies
        FROM gaps WHERE gap_h IS NOT NULL
        GROUP BY core_hash
    """).fetchall()
    out: dict[str, dict] = {}
    for core_hash, max_gap_h, n_dormancies in rows:
        out[core_hash] = {
            "max_gap_h":    round(float(max_gap_h or 0.0), 1),
            "n_dormancies": int(n_dormancies or 0),
            "re_emergent":  bool((n_dormancies or 0) >= 1),
        }
    return out


def pat_fingerprint_rotation(con) -> list[dict]:
    """Behavioral fingerprints deployed across rotated infrastructure.

    compositeprint fuses each source's stack + proto/port sequence + timing +
    app (TLS/HTTP/SSH) + payload into one ``core_hash`` that is deliberately
    independent of ASN/CIDR/IP.  The SAME core_hash observed from many ASNs is
    therefore one tool/campaign that has rotated its hosting -- exactly the
    behaviour-survives-infrastructure signal that per-IP analyzers cannot see.

    This rule surfaces the widely-distributed behavioral clusters (>= N ASNs),
    drops generic ICMP ping sweeps, and enriches each with the dormancy/
    re-emergence structure of its episode timeline.  Severity rises with the
    breadth of the rotation and when the fingerprint carries an app or payload
    (i.e. is distinctive, not a bare scan).  Distinct from the ML-cluster
    ``infra_rotation`` longitudinal module: this keys on the exact fused
    fingerprint, not a statistical actor cluster.
    """
    if not _have(con, "composite_clusters"):
        return []
    clusters = con.execute(f"""
        SELECT core_hash, n_ips, n_episodes, n_asns, n_cidrs, n_countries,
               total_packets, first_seen, last_seen, span_hours, present,
               dom_proto, rep_port, seq_chain, tempo_chain, sample_ips,
               sample_asns, tier
        FROM composite_clusters
        WHERE cross_infra = TRUE
          AND n_asns >= {COMPOSITE_MIN_ASNS}
          AND seq_chain NOT LIKE 'ICMP/8.0%'
        ORDER BY n_asns DESC, n_ips DESC, total_packets DESC
        LIMIT {COMPOSITE_TOP_ROTATION}
    """).fetchall()
    if not clusters:
        return []

    timeline = _rotation_timeline(con, [c[0] for c in clusters])

    out: list[dict] = []
    for (core_hash, n_ips, n_eps, n_asns, n_cidrs, n_countries, pkts, ts0, ts1,
         span_h, present, dom_proto, rep_port, seq, tempo, sample_ips,
         sample_asns, tier) in clusters:
        tl = timeline.get(core_hash, {})
        re_emergent = tl.get("re_emergent", False)
        has_app = present and present.startswith("a")
        has_payload = present and present.endswith("p")

        tells = ["cross-infra"]
        if n_asns >= COMPOSITE_HIGH_ASNS:
            tells.append("wide-rotation")
        if has_app:
            tells.append("app-bearing")
        if has_payload:
            tells.append("payload-bearing")
        if re_emergent:
            tells.append("re-emergent")

        sev = "medium"
        if n_asns >= COMPOSITE_HIGH_ASNS:
            sev = "high"
        elif (has_app or has_payload) and n_asns >= 4:
            sev = "high"
        elif re_emergent and n_asns >= 4:
            sev = "high"

        ip_list = [s for s in (sample_ips or "").split(",") if s]
        asn_list = [a for a in (sample_asns or "").split(",") if a]
        out.append(_finding(
            pattern_id=f"fp_rotation_{core_hash[:12]}",
            pattern_title=(f"Behavioral fingerprint across {int(n_asns)} ASNs "
                           f"/ {int(n_ips)} IPs ({tier})"),
            severity=sev,
            category="infrastructure-rotation",
            src_ips=ip_list,
            asns=asn_list,
            key_metrics={
                "core_hash":     core_hash,
                "n_ips":         int(n_ips),
                "n_asns":        int(n_asns),
                "n_cidrs":       int(n_cidrs),
                "n_countries":   int(n_countries or 0),
                "n_episodes":    int(n_eps or 0),
                "packet_count":  int(pkts or 0),
                "span_hours":    round(float(span_h or 0), 1),
                "present":       present or "",
                "dom_proto":     dom_proto or "",
                "rep_port":      int(rep_port or 0),
                "sequence":      (seq or "")[:256],
                "tempo":         (tempo or "")[:256],
                "re_emergent":   bool(re_emergent),
                "max_gap_hours": tl.get("max_gap_h", 0.0),
                "dormancies":    tl.get("n_dormancies", 0),
                "tells":         tells,
            },
            evidence_refs=[{"section": "compositeprint",
                            "label": "Fused multi-dimensional fingerprint"}],
            report_anchor="#composite-fingerprints-compositeprint",
            first_seen=str(ts0), last_seen=str(ts1),
        ))
    return out


def _asn_communities(edge_list: list[tuple[int, int, int]]) -> list[set]:
    """Partition the weighted ASN co-host graph into communities.

    Louvain (python-louvain, weighted by shared campaigns) when available --
    deterministic via a fixed seed -- so a few hub ASNs don't transitively
    fuse the whole graph into one blob.  Falls back to connected components
    (union-find) when the graph libs aren't installed.
    """
    try:
        import networkx as nx
        import community as community_louvain
        g = nx.Graph()
        for a, b, w in edge_list:
            g.add_edge(a, b, weight=w)
        part = community_louvain.best_partition(g, weight="weight",
                                                random_state=42)
        comms: dict[int, set] = {}
        for node, cid in part.items():
            comms.setdefault(cid, set()).add(node)
        return list(comms.values())
    except Exception:
        parent: dict[int, int] = {}

        def find(x: int) -> int:
            parent.setdefault(x, x)
            root = x
            while parent[root] != root:
                root = parent[root]
            while parent[x] != root:
                parent[x], x = root, parent[x]
            return root

        for a, b, _w in edge_list:
            parent[find(a)] = find(b)
        comps: dict[int, set] = {}
        for a, b, _w in edge_list:
            comps.setdefault(find(a), set()).update((a, b))
        return list(comps.values())


def pat_bulletproof_asn_cluster(con) -> list[dict]:
    """Communities of ASNs that host the SAME migrating campaign fingerprints
    AND carry bulletproof signals.

    campaignmigration's ISP-collaboration graph links two ASNs when they
    co-host the same compositeprint ``core_hash`` (a behaviour, independent of
    infrastructure).  Louvain communities of that graph are candidate
    operator-aligned network groups.  This rule keeps the communities that also
    light up asnintel's per-ASN signals -- a ``bulletproof_flag`` or a
    block-grade ``risk_grade`` (block_asn / monitor_block) -- i.e. the
    complicit / bulletproof hosting cluster a campaign rotates through to evade
    filtering.  (A high mean ``cooperation_score`` is reported as a tell but is
    NOT a trigger on its own -- benign synchronized scanners score high there.)
    Per-ASN flags come from asnintel; the *cluster* (which ASNs act together)
    is the new signal this rule adds on top.
    """
    if not _have(con, "isp_collab") or not _have(con, "asnintel"):
        return []
    raw = con.execute(f"""
        SELECT src_asn, dst_asn, shared_campaigns
        FROM isp_collab
        WHERE kind = 'cohost' AND shared_campaigns >= {BP_CLUSTER_MIN_EDGE}
    """).fetchall()
    if not raw:
        return []
    edge_list = [(int(a), int(b), int(w)) for a, b, w in raw]

    # Partition the collaboration graph into COMMUNITIES (Louvain, weighted by
    # shared campaigns) rather than raw connected components: a few hub ASNs
    # (big hosters) otherwise transitively fuse everything into one giant blob.
    # Communities carve out the tight operator-aligned sub-clusters.  Falls back
    # to connected components if python-louvain/networkx are unavailable.
    groups = _asn_communities(edge_list)

    all_asns = {a for a, _b, _w in edge_list} | {b for _a, b, _w in edge_list}
    info: dict[int, dict] = {}
    ph = ",".join(str(a) for a in all_asns)
    for asn, org, ctry, bp, coop, grade, dens in con.execute(f"""
        SELECT asn, asn_org, country_iso, bulletproof_flag,
               cooperation_score, risk_grade, threat_density
        FROM asnintel WHERE asn IN ({ph})
    """).fetchall():
        info[int(asn)] = {
            "org": org or "", "country": ctry or "",
            "bp": bool(bp), "coop": float(coop or 0.0),
            "grade": grade or "", "density": float(dens or 0.0)}

    out: list[dict] = []
    for asn_set in groups:
        asns = sorted(asn_set)
        if len(asns) < BP_CLUSTER_MIN_ASNS:
            continue
        infos = [info.get(a, {}) for a in asns]
        bp_asns = [a for a in asns if info.get(a, {}).get("bp")]
        block_asns = [a for a in asns
                      if info.get(a, {}).get("grade") in ("block_asn", "monitor_block")]
        coops = [i["coop"] for i in infos if i]
        mean_coop = sum(coops) / len(coops) if coops else 0.0
        # TRIGGER on actual bulletproof hosting: a bulletproof_flag or a
        # block-grade ASN in the cluster.  High coordination ALONE is not
        # enough -- benign synchronized scanners (Censys, Shadowserver) also
        # score high there; it's kept only as an enrichment tell.
        if not (bp_asns or block_asns):
            continue
        links_w = sum(w for a, b, w in edge_list
                      if a in asn_set and b in asn_set)

        countries = sorted({i.get("country", "") for i in infos if i.get("country")})
        tells = []
        if bp_asns:
            tells.append(f"{len(bp_asns)}-bulletproof")
        if block_asns:
            tells.append(f"{len(block_asns)}-block-grade")
        if mean_coop >= BP_CLUSTER_COOP_HIGH:
            tells.append("high-coordination")
        sev = "high" if (bp_asns or len(block_asns) >= 2 or len(asns) >= 6) else "medium"
        labels = ", ".join(f"AS{a}({info.get(a, {}).get('org', '')[:14]})"
                           for a in asns[:12])

        out.append(_finding(
            pattern_id=f"bp_asn_cluster_{hashlib.sha256(str(asns).encode()).hexdigest()[:8]}",
            pattern_title=(f"Bulletproof ASN cluster: {len(asns)} networks "
                           f"sharing {links_w} campaign links"),
            severity=sev,
            category="bulletproof-hosting",
            src_ips=[],
            asns=[f"AS{a}" for a in asns],
            countries=countries,
            key_metrics={
                "n_asns":                len(asns),
                "asns":                  [f"AS{a}" for a in asns],
                "asn_labels":            labels,
                "shared_campaign_links": links_w,
                "bulletproof_asns":      [f"AS{a}" for a in bp_asns],
                "block_grade_asns":      [f"AS{a}" for a in block_asns],
                "mean_cooperation_score": round(mean_coop, 3),
                "countries":             countries,
                "tells":                 tells,
            },
            evidence_refs=[
                {"section": "campaignmigration",
                 "label": "ISP-collaboration graph (shared campaign fingerprints)"},
                {"section": "asnintel",
                 "label": "Per-ASN bulletproof / cooperation signals"}],
            report_anchor="#28-campaign-migration-across-infrastructure-campaignmigration",
            first_seen="", last_seen="",
        ))
    out.sort(key=lambda f: -json.loads(f["key_metrics"])["n_asns"])
    return out[:BP_CLUSTER_TOP]


PATTERNS: list[Callable] = [
    pat_telco_ss7_recon,
    pat_routing_protocol_on_public_ip,
    pat_ipsec_probe_from_scanner,
    pat_covert_tunnel_setup,
    pat_multi_transport_bulletproof,
    pat_botnet_in_coordination_wave,
    pat_synchronized_campaign_burst,
    pat_recent_tight_campaign,
    pat_bulletproof_high_density,
    pat_rdp_credential_spray,
    pat_low_slow_subnet_coordinated,
    pat_wrong_proto_amp_endpoints,
    pat_icmp_payload_anomalies,
    pat_tcp_midstream_spoof,
    pat_global_arrival_burst,
    pat_local_only_vnc_targeting,
    pat_self_mimic_honeypot_aware,
    pat_anomalous_chain,
    pat_fingerprint_rotation,
    pat_bulletproof_asn_cluster,
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
        ("chainfp",          R / "chainfp" / "chainfp.parquet"),
        ("chainfp_snr",      R / "chainfp" / "window_snr.parquet"),
        ("chainfp_timed",    R / "chainfp" / "chainfp_timed.parquet"),
        ("composite_ep",     R / "compositeprint" / "composite.parquet"),
        ("composite_clusters", R / "compositeprint" / "clusters.parquet"),
        ("isp_collab",       R / "campaignmigration" / "isp_collab.parquet"),
    ]
    for view, path in mapping:
        if not path.exists():
            continue
        con.execute(
            f"CREATE OR REPLACE VIEW {view} AS "
            f"SELECT * FROM read_parquet('{path.as_posix()}')"
        )
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

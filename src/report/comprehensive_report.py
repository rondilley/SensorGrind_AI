#!/usr/bin/env python3
"""
report/comprehensive_report — unified threat-intelligence report.

Consumes every analyzer output (data/reports/*, data/risk/*,
data/patterns/*, data/features/*, data/models/*) and produces a
single comprehensive markdown report combining:

  - Executive summary with top-line metrics
  - Statistical distributions (histograms, percentile tables)
  - Mermaid diagrams: pie, xychart, sequence, gantt, flowchart
  - ASCII heatmaps for time-of-day / day-of-week activity
  - Risk stratification and per-tier breakdowns
  - Attack chain reconstruction and sequencing
  - Coordinated wave detection
  - Pattern mining + auto-promoted rule summary
  - ML model performance + feature drift signals
  - Survival analysis by cohort
  - Detection gaps and recommended actions
  - Per-analyzer data-quality appendix

Output: three formats in output/reports/
  COMPREHENSIVE.md   (canonical markdown source)
  COMPREHENSIVE.html (browser-rendered, Mermaid live via CDN)
  COMPREHENSIVE.pdf  (Mermaid blocks pre-rendered to SVG via mmdc)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import features as sf
from sg import lib
from conclusions import verdict
# Rendering primitives moved to render.py so this file can focus on
# section composition.  Re-export the constants the rest of the code
# expects so existing call sites keep working.
from report.render import (
    OUT_PATH, HTML_PATH, PDF_PATH, VISUALS_DIR,
    MMDC, PUPPETEER_CONFIG,
    mermaid_pie, mermaid_xychart_bar, mermaid_xychart_line,
    mermaid_sequence, mermaid_flowchart, mermaid_sankey, mermaid_gantt,
    mm_trunc,
    svg_bar_chart, svg_line_chart, svg_gantt_chart, smart_bar, smart_line,
    mermaid_histogram, percentile_table, svg_heatmap,
    render_mermaid_to_svg, md_to_html_body, write_html,
    prerender_mermaid_for_pdf, write_pdf,
    safe_read_table, safe_columns,
    HTML_STYLE, HTML_HEAD,
)


def sensor_outages() -> list[tuple[_dt.date, _dt.date, int]]:
    """(first, last, n_days) for each run of UTC days with no packets.

    The parser writes one ``packets/dt=YYYY-MM-DD`` partition per UTC day
    that saw traffic, so a missing partition is a whole day the sensor
    recorded nothing.  Sub-day gaps are sensormask's job."""
    days = sorted(_dt.date.fromisoformat(p.name[3:])
                  for p in (lib.PARQUET / "packets").glob("dt=*"))
    one = _dt.timedelta(days=1)
    return [(a + one, b - one, (b - a).days - 1)
            for a, b in zip(days, days[1:]) if (b - a).days > 1]


# ----------------------------------------------------------------------
# Main report builder
# ----------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    con = lib.duck(memory_limit="12GB")
    lib.register_views(con)

    snap = sf.latest_snapshot("ip", 1)
    snap_date = snap.snapshot_date if snap else _dt.date.today()
    feat_path = sf.snapshot_dir(snap) / "part-0000.parquet" if snap else None
    risk_path = (lib.OUTPUT_DIR / "risk" / "ip_risk" / f"dt={snap_date.isoformat()}" / "risk.parquet")

    print("[report] gathering top-line metrics...", file=sys.stderr)
    totals = con.execute("""
        SELECT count(*) AS packets, count(DISTINCT src_ip) AS ips,
               min(ts) AS first_ts, max(ts) AS last_ts,
               count(DISTINCT dt) AS days,
               sum(pkt_len) AS bytes
        FROM packets
    """).fetchone()
    total_packets, total_ips, first_ts, last_ts, total_days, total_bytes = totals
    blob_count = con.execute("SELECT count(*) FROM payload_blobs").fetchone()[0]
    l7_count = con.execute("SELECT count(*) FROM l7_events").fetchone()[0]
    ioc_count = con.execute("SELECT count(*) FROM iocs").fetchone()[0]

    # ---- risk tier counts ----
    tier_counts: dict[str, int] = {}
    risk_top: list[tuple] = []
    risk_score_values: list[float] = []
    ml_score_values: list[float] = []
    if risk_path.exists():
        tier_rows = con.execute(f"""
            SELECT risk_tier, count(*) FROM read_parquet('{risk_path}')
            GROUP BY risk_tier
        """).fetchall()
        tier_counts = {r[0]: int(r[1]) for r in tier_rows}
        risk_top = con.execute(f"""
            SELECT src_ip, risk_score, risk_tier, ml_score, rationale
            FROM read_parquet('{risk_path}')
            ORDER BY risk_score DESC LIMIT 25
        """).fetchall()
        # Sample 50k risk scores for histogram (full dataset = 990k rows).
        sample = con.execute(f"""
            SELECT risk_score, ml_score FROM read_parquet('{risk_path}')
            USING SAMPLE 50000 ROWS
        """).fetchall()
        risk_score_values = [r[0] for r in sample]
        ml_score_values = [r[1] for r in sample]

    # ---- benignfilter summary ----
    benign_org_counts = lib.load_report(
        con, lib.REPORTS / "benignfilter" / "benignfilter.parquet",
        "SELECT org, count(*), sum(pkt_count) FROM {path} "
        "GROUP BY org ORDER BY count(*) DESC",
    )

    # ---- geographic breakdown ----
    geo_rows = []
    if feat_path and feat_path.exists():
        geo_rows = con.execute(f"""
            SELECT country_iso, count(*) AS ips
            FROM read_parquet('{feat_path}')
            WHERE country_iso IS NOT NULL AND country_iso != ''
            GROUP BY country_iso ORDER BY ips DESC LIMIT 20
        """).fetchall()

    asn_rows = []
    if feat_path and feat_path.exists():
        asn_rows = con.execute(f"""
            SELECT asn_org, count(*) AS ips, sum(pkt_count) AS pkts
            FROM read_parquet('{feat_path}')
            WHERE asn_org IS NOT NULL AND asn_org != ''
            GROUP BY asn_org ORDER BY pkts DESC LIMIT 20
        """).fetchall()

    # ---- protocol mix ----
    proto_rows = con.execute("""
        SELECT proto, count(*) FROM packets GROUP BY proto
    """).fetchall()
    proto_mix = {lib.PROTO_NAME.get(p, str(p)): n for p, n in proto_rows}

    l7_rows = con.execute("""
        SELECT l7_proto, count(*) FROM l7_events GROUP BY l7_proto
    """).fetchall()
    l7_mix = {lib.L7_NAME.get(p, str(p)): n for p, n in l7_rows}

    # ---- workhours heatmap ----
    heat_grid: dict[tuple[int, int], int] = {}
    for d, h, c in lib.load_report(
        con, lib.REPORTS / "workhours" / "workhours.parquet",
        "SELECT dow, hour_utc, pkt_count FROM {path}",
    ):
        heat_grid[(int(d), int(h))] = int(c)

    # ---- attack chains ----
    chain_rows = lib.load_report(
        con, lib.OUTPUT_DIR / "patterns" / "attack_chains" / "patterns.parquet",
        "SELECT chain, ip_count, avg_span_d, avg_risk FROM {path} "
        "ORDER BY ip_count DESC LIMIT 25",
    )

    # ---- sequences ----
    seq_path = lib.OUTPUT_DIR / "patterns" / "sequences" / "ngrams.parquet"
    seq_rows: list = []
    transitions: list = []
    if seq_path.exists():
        seq_rows = con.execute(f"""
            SELECT ngram, length, ip_count, support_pct
            FROM read_parquet('{seq_path}')
            ORDER BY ip_count DESC LIMIT 20
        """).fetchall()
        # Length-2 transitions = the real per-stage edges in the chain graph.
        transitions = con.execute(f"""
            SELECT ngram, ip_count, support_pct
            FROM read_parquet('{seq_path}')
            WHERE length = 2
            ORDER BY ip_count DESC
        """).fetchall()

    # ---- coordination waves (campaigns + always-on background) ----
    wave_path = lib.OUTPUT_DIR / "patterns" / "coordination" / "payload_waves.parquet"
    # Top-N campaigns by density_score (ip_count * corpus_span / burst_window).
    # Filtered to is_campaign=true so always-on background payloads
    # (whose senders span the entire corpus) don't pollute the view.
    campaign_rows: list = []
    # Per-month new-campaign-launch counts (driven by launch_ts).
    campaign_launches_by_month: list = []
    # Largest wave (any payload) — used in the executive summary bullet.
    biggest_wave: tuple | None = None
    if wave_path.exists():
        campaign_rows = con.execute(f"""
            SELECT ip_count, launch_ts, peak_day, decay_ts,
                   burst_window_days, peak_count, l7_proto, sample_ips,
                   density_score
            FROM read_parquet('{wave_path}')
            WHERE is_campaign = TRUE
            ORDER BY density_score DESC LIMIT 50
        """).fetchall()
        campaign_launches_by_month = con.execute(f"""
            SELECT strftime(launch_ts, '%Y-%m') AS ym, count(*) AS n
            FROM read_parquet('{wave_path}')
            WHERE is_campaign = TRUE AND launch_ts IS NOT NULL
            GROUP BY ym ORDER BY ym
        """).fetchall()
        biggest_row = con.execute(f"""
            SELECT ip_count, first_seen, last_seen, span_minutes,
                   median_ipd_sec, l7_proto, sample_ips
            FROM read_parquet('{wave_path}')
            ORDER BY ip_count DESC LIMIT 1
        """).fetchone()
        if biggest_row is not None:
            biggest_wave = biggest_row
    # Keep an alias for the executive-summary bullet path below.
    wave_rows = [biggest_wave] if biggest_wave else []

    burst_rows = lib.load_report(
        con, lib.OUTPUT_DIR / "patterns" / "coordination" / "arrival_bursts.parquet",
        "SELECT bucket_start, new_ip_count, ratio FROM {path} "
        "ORDER BY ratio DESC LIMIT 15",
    )

    # ---- itemsets / rules ----
    cand_path = lib.OUTPUT_DIR / "patterns" / "candidate_rules.parquet"
    auto_rules = queued_rules = []
    if cand_path.exists():
        auto_rules = con.execute(f"""
            SELECT rule_id, itemset_str, ip_count, threat_pct, avg_risk
            FROM read_parquet('{cand_path}')
            WHERE disposition = 'auto_promoted'
            ORDER BY ip_count DESC LIMIT 20
        """).fetchall()
        queued_rules = con.execute(f"""
            SELECT rule_id, itemset_str, ip_count, threat_pct, avg_risk, sample_ips
            FROM read_parquet('{cand_path}')
            WHERE disposition = 'queued'
            ORDER BY ip_count DESC LIMIT 20
        """).fetchall()

    # ---- HDBSCAN clusters ----
    cluster_rows = lib.load_report(
        con, lib.OUTPUT_DIR / "patterns" / "actor_clusters" / "summary.parquet",
        "SELECT cluster_id, size, top_country, top_asn_org, avg_port_count, "
        "dominant_l7, benign_fraction, botnet_fraction, sample_ips "
        "FROM {path} ORDER BY size DESC LIMIT 20",
    )

    # ---- drift ----
    drift_path = lib.OUTPUT_DIR / "patterns" / "drift" / "drift.parquet"
    drift_rows = []
    if drift_path.exists():
        drift_rows = con.execute(f"""
            SELECT feature, ks_statistic, p_value, baseline_mean, recent_mean, significant
            FROM read_parquet('{drift_path}')
            ORDER BY ks_statistic DESC
        """).fetchall()

    # ---- model registry ----
    from sg import models as sm
    registry = sm.list_models()

    # ---- probesigs distribution ----
    probesigs_path = lib.REPORTS / "probesigs" / "probesigs.parquet"
    probe_rows = []
    if probesigs_path.exists():
        probe_rows = con.execute(f"""
            SELECT probe_tag, count(*) FROM read_parquet('{probesigs_path}')
            GROUP BY probe_tag ORDER BY count(*) DESC LIMIT 25
        """).fetchall()

    # ---- botnet family distribution ----
    botnet_path = lib.REPORTS / "botnetcls" / "botnetcls.parquet"
    fam_rows = []
    if botnet_path.exists():
        fam_rows = con.execute(f"""
            SELECT family, count(*) FROM read_parquet('{botnet_path}')
            GROUP BY family ORDER BY count(*) DESC
        """).fetchall()

    # ---- survival ----
    surv_path = lib.OUTPUT_DIR / "patterns" / "survival" / "cohorts.parquet"
    surv_rows = []
    if surv_path.exists():
        surv_rows = con.execute(f"""
            SELECT cohort_kind, cohort, ip_count, median_d, p75_d, p90_d, active_pct
            FROM read_parquet('{surv_path}')
            ORDER BY ip_count DESC LIMIT 30
        """).fetchall()

    # ---- cross-modal lag ----
    lag_path = lib.OUTPUT_DIR / "patterns" / "cross_modal_lag" / "lag_pairs.parquet"
    lag_rows = []
    if lag_path.exists():
        lag_rows = con.execute(f"""
            SELECT series_a, series_b, lag_days, correlation
            FROM read_parquet('{lag_path}')
            ORDER BY abs(correlation) DESC LIMIT 20
        """).fetchall()

    # ---- emergence ----
    emerge_path = lib.REPORTS / "emergence" / "emergence.parquet"
    emerge_rows = []
    if emerge_path.exists():
        emerge_rows = con.execute(f"""
            SELECT entity_type, count(*) FROM read_parquet('{emerge_path}')
            GROUP BY entity_type ORDER BY count(*) DESC
        """).fetchall()

    # ---- daily volume series for time chart ----
    print("[report] computing daily volume series...", file=sys.stderr)
    daily = con.execute("""
        SELECT date_trunc('month', ts)::DATE AS m,
               count(*) AS pkts,
               count(DISTINCT src_ip) AS ips
        FROM packets GROUP BY m ORDER BY m
    """).fetchall()

    # ---- v2.3: asnintel ----
    asn_rows_intel = []
    asn_path = lib.REPORTS / "asnintel" / "asnintel.parquet"
    if asn_path.exists():
        asn_rows_intel = con.execute(f"""
            SELECT asn, asn_org, country_iso, ip_count, threat_ip_count,
                   threat_density, cooperation_score, bulletproof_flag,
                   top_ports, top_botnet_fams, top_probe_tags,
                   risk_grade, block_recommend
            FROM read_parquet('{asn_path}')
            ORDER BY threat_ip_count DESC LIMIT 30
        """).fetchall()

    # ---- v2.3: cidrintel ----
    cidr24_rows = []
    cidr16_rows = []
    cidr_path = lib.REPORTS / "cidrintel" / "cidrintel.parquet"
    if cidr_path.exists():
        cidr24_rows = con.execute(f"""
            SELECT cidr, ip_count, threat_ip_count, threat_density,
                   top_asn_org, top_country, top_botnet_fam, top_dst_port,
                   block_recommend
            FROM read_parquet('{cidr_path}')
            WHERE prefix_len = 24
            ORDER BY block_score DESC LIMIT 25
        """).fetchall()
        cidr16_rows = con.execute(f"""
            SELECT cidr, ip_count, threat_ip_count, threat_density,
                   top_asn_org, top_country, top_botnet_fam, top_dst_port,
                   block_recommend
            FROM read_parquet('{cidr_path}')
            WHERE prefix_len = 16
            ORDER BY block_score DESC LIMIT 15
        """).fetchall()

    # ---- v2.3: tooling ----
    tool_summary = []
    tool_path = lib.REPORTS / "tooling" / "tooling.parquet"
    if tool_path.exists():
        tool_summary = con.execute(f"""
            SELECT dominant_tool, count(*) AS ips
            FROM read_parquet('{tool_path}')
            GROUP BY dominant_tool ORDER BY ips DESC LIMIT 20
        """).fetchall()

    # ---- v2.3: actorlink + originintel ----
    actor_communities = []
    al_path = lib.REPORTS / "actorlink" / "communities.parquet"
    if al_path.exists():
        actor_communities = con.execute(f"""
            SELECT community_id, member_count, avg_risk, countries, top_asns,
                   shared_signals, dominant_tools, dominant_targets,
                   first_seen, last_seen, sample_ips
            FROM read_parquet('{al_path}')
            ORDER BY member_count DESC LIMIT 15
        """).fetchall()
    actor_profiles_map: dict[int, dict] = {}
    oi_path = lib.REPORTS / "originintel" / "profiles.parquet"
    if oi_path.exists():
        prof_rows = con.execute(f"""
            SELECT community_id, candidate_name, likely_actor_class, tooling,
                   ttp, targets, defender_actions, confidence, rationale,
                   provider, model
            FROM read_parquet('{oi_path}')
        """).fetchall()
        for r in prof_rows:
            actor_profiles_map[int(r[0])] = {
                "candidate_name":     r[1], "likely_actor_class": r[2],
                "tooling":            r[3], "ttp":                r[4],
                "targets":            r[5], "defender_actions":   r[6],
                "confidence":         r[7], "rationale":          r[8],
                "provider":           r[9], "model":              r[10],
            }

    # ---- v2.2: pktanalysis ----
    pkt_flag_rows = []
    pkt_anom_rows = []
    pkt_ttl_rows = []
    pkt_dir = lib.REPORTS / "pktanalysis"
    if (pkt_dir / "tcp_flag_combos.parquet").exists():
        pkt_flag_rows = con.execute(f"""
            SELECT flag_label, flag_mask, packets, share_pct, anomaly
            FROM read_parquet('{pkt_dir}/tcp_flag_combos.parquet')
            ORDER BY packets DESC LIMIT 20
        """).fetchall()
    if (pkt_dir / "header_anomalies.parquet").exists():
        pkt_anom_rows = con.execute(f"""
            SELECT anomaly, packets, distinct_ips, share_per_million
            FROM read_parquet('{pkt_dir}/header_anomalies.parquet')
            ORDER BY packets DESC
        """).fetchall()
    if (pkt_dir / "ttl_dist.parquet").exists():
        pkt_ttl_rows = con.execute(f"""
            SELECT ttl_bucket, os_family_hint, packets, distinct_ips
            FROM read_parquet('{pkt_dir}/ttl_dist.parquet')
            ORDER BY ttl_bucket
        """).fetchall()

    # ---- v2.2: payloadanalysis ----
    pl_enc_rows = []
    pl_prefix_rows = []
    pl_dir = lib.REPORTS / "payloadanalysis"
    if (pl_dir / "encoding_dist.parquet").exists():
        pl_enc_rows = con.execute(f"""
            SELECT encoding, sum(blobs) AS blobs, sum(blobs*share_pct)/sum(blobs) AS share_pct
            FROM read_parquet('{pl_dir}/encoding_dist.parquet')
            GROUP BY encoding ORDER BY blobs DESC
        """).fetchall()
    if (pl_dir / "prefix_dist.parquet").exists():
        pl_prefix_rows = con.execute(f"""
            SELECT prefix_hex, printable_prefix, l7_proto, blobs
            FROM read_parquet('{pl_dir}/prefix_dist.parquet')
            ORDER BY blobs DESC LIMIT 25
        """).fetchall()

    # ---- v2.2: pacing ----
    pace_rows = []
    pace_flow_rows = []
    pace_dir = lib.REPORTS / "pacing"
    if (pace_dir / "per_ip.parquet").exists():
        pace_rows = con.execute(f"""
            SELECT src_ip, pkt_count, iat_median_s, iat_cv, beacon_60s, beacon_300s, metronome
            FROM read_parquet('{pace_dir}/per_ip.parquet')
            WHERE metronome = true
            ORDER BY iat_cv ASC LIMIT 25
        """).fetchall()
    if (pace_dir / "flow_duration.parquet").exists():
        pace_flow_rows = con.execute(f"""
            SELECT dur_bucket, flows FROM read_parquet('{pace_dir}/flow_duration.parquet')
            ORDER BY flows DESC
        """).fetchall()

    # ---- v2.2: landscape (monthly top ports) ----
    landscape_dir = lib.REPORTS / "landscape"
    landscape_port_rows = []
    landscape_fam_rows = []
    if (landscape_dir / "monthly_top_ports.parquet").exists():
        landscape_port_rows = con.execute(f"""
            SELECT month, dst_port, distinct_ips, rank
            FROM read_parquet('{landscape_dir}/monthly_top_ports.parquet')
            WHERE rank <= 5 ORDER BY month, rank
        """).fetchall()
    if (landscape_dir / "monthly_botnet.parquet").exists():
        landscape_fam_rows = con.execute(f"""
            SELECT month, family, ips
            FROM read_parquet('{landscape_dir}/monthly_botnet.parquet')
            ORDER BY month, ips DESC
        """).fetchall()

    # ---- v2.2: protocolanomaly ----
    proto_state_rows = []
    proto_wrong_rows = []
    proto_cross_rows = []
    proto_dir = lib.REPORTS / "protocolanomaly"
    if (proto_dir / "tcp_state.parquet").exists():
        proto_state_rows = con.execute(f"""
            SELECT anomaly_kind, packets, distinct_ips
            FROM read_parquet('{proto_dir}/tcp_state.parquet')
            ORDER BY packets DESC
        """).fetchall()
    if (proto_dir / "wrong_proto_port.parquet").exists():
        proto_wrong_rows = con.execute(f"""
            SELECT proto, dst_port, packets, ips, note
            FROM read_parquet('{proto_dir}/wrong_proto_port.parquet')
            ORDER BY packets DESC LIMIT 20
        """).fetchall()
    if (proto_dir / "cross_proto.parquet").exists():
        proto_cross_rows = con.execute(f"""
            SELECT src_ip, uses_tcp, uses_udp, uses_icmp,
                   payload_tcp, payload_udp, payload_icmp, multi_proto_score
            FROM read_parquet('{proto_dir}/cross_proto.parquet')
            ORDER BY multi_proto_score DESC, payload_tcp + payload_udp + payload_icmp DESC
            LIMIT 25
        """).fetchall()

    # ---- v2.2: ISC compare ----
    isc_dir = lib.REPORTS / "isc_compare"
    isc_local_only = []
    isc_only_rows = []
    isc_shared = []
    if (isc_dir / "port_compare.parquet").exists():
        isc_local_only = con.execute(f"""
            SELECT port, local_packets, local_ips
            FROM read_parquet('{isc_dir}/port_compare.parquet')
            WHERE status = 'local_only'
            ORDER BY local_packets DESC LIMIT 15
        """).fetchall()
        isc_only_rows = con.execute(f"""
            SELECT port, isc_records, isc_targets
            FROM read_parquet('{isc_dir}/port_compare.parquet')
            WHERE status = 'isc_only'
            ORDER BY isc_records DESC LIMIT 15
        """).fetchall()
        isc_shared = con.execute(f"""
            SELECT port, isc_records, local_packets, local_ips
            FROM read_parquet('{isc_dir}/port_compare.parquet')
            WHERE status = 'shared'
            ORDER BY local_packets DESC LIMIT 15
        """).fetchall()

    # ---- v2.2: nonipproto ----
    nonip_rows = []
    nonip_path = lib.REPORTS / "nonipproto" / "nonipproto.parquet"
    if nonip_path.exists():
        nonip_rows = con.execute(f"""
            SELECT proto_num, proto_name, description, packets, total_bytes,
                   distinct_srcs, ttl_mode, first_seen, last_seen,
                   sample_src, sample_hex, sample_printable
            FROM read_parquet('{nonip_path}')
            ORDER BY packets DESC LIMIT 30
        """).fetchall()

    # ---- v2.2: AI payload decode (per non-TCP/UDP/ICMP protocol) ----
    aidecode_map: dict[int, dict] = {}
    ai_path = lib.REPORTS / "ai_decode" / "decodes.parquet"
    if ai_path.exists():
        ar = con.execute(f"""
            SELECT proto_num, identified_as, confidence, decoded_fields,
                   threat_level, threat_summary, analysis, model
            FROM read_parquet('{ai_path}')
            WHERE source LIKE 'nonipproto:%'
        """).fetchall()
        for pn, ident, conf, fields_json, lvl, summ, analysis, model in ar:
            aidecode_map[int(pn)] = {
                "identified_as":  ident, "confidence": conf,
                "decoded_fields": fields_json, "threat_level": lvl,
                "threat_summary": summ, "analysis": analysis, "model": model,
            }

    # ---- v2.7: chainfp - per-IP packet choreography fingerprints ----
    # Each chain is a per-source-IP sequence of (flag_mask, proto, port) tokens
    # within one adaptive session (sensorChain.pl grammar).  window_snr scores
    # each candidate window by chain-frequency entropy and flags the winner.
    chainfp_best: dict = {}
    chainfp_snr_rows: list = []
    chainfp_distinctive: list = []
    chainfp_path = lib.REPORTS / "chainfp" / "chainfp.parquet"
    chainfp_snr_path = lib.REPORTS / "chainfp" / "window_snr.parquet"
    chainfp_timed_path = lib.REPORTS / "chainfp" / "chainfp_timed.parquet"
    chainfp_best_label = None
    if chainfp_snr_path.exists():
        chainfp_snr_rows = con.execute(f"""
            SELECT window_label, window_seconds, distinct_chains,
                   total_chain_obs, entropy_bits, is_best
            FROM read_parquet('{chainfp_snr_path}')
            ORDER BY entropy_bits DESC
        """).fetchall()
        best = [r for r in chainfp_snr_rows if r[5]]
        if best:
            b = best[0]
            chainfp_best_label = b[0]
            chainfp_best = {"label": b[0], "window_seconds": b[1],
                            "distinct_chains": b[2], "entropy_bits": b[4]}
    if chainfp_path.exists() and chainfp_best_label:
        chainfp_distinctive = con.execute(f"""
            SELECT chain, source_count, packet_count, token_count,
                   top_dst_ports, anomaly_tier
            FROM read_parquet('{chainfp_path}')
            WHERE window_label = '{chainfp_best_label}'
              AND anomaly_tier IN ('distinctive', 'rare')
              AND token_count >= 3
              AND chain NOT LIKE 'ICMP/8.0,ICMP/8.0,ICMP/8.0%'
            ORDER BY source_count DESC, packet_count DESC
            LIMIT 25
        """).fetchall()

    # ---- v2.8: compositeprint - fused multi-dimensional fingerprints ----
    # Per (src_ip, adaptive episode) the stack + proto/port sequence + timing +
    # app + payload are fused into an infra-independent core_hash; clusters.parquet
    # rolls those up per fingerprint and flags the cross-infrastructure ones.
    composite_summary: dict = {}
    composite_cross_rows: list = []
    comp_clusters_path = lib.REPORTS / "compositeprint" / "clusters.parquet"
    comp_ep_path = lib.REPORTS / "compositeprint" / "composite.parquet"
    if comp_ep_path.exists():
        s = con.execute(f"""
            SELECT count(*) AS episodes, count(DISTINCT src_ip) AS ips,
                   count(DISTINCT core_hash) AS cores
            FROM read_parquet('{comp_ep_path}')
        """).fetchone()
        composite_summary = {"episodes": s[0], "ips": s[1], "cores": s[2]}
    if comp_clusters_path.exists():
        c = con.execute(f"""
            SELECT count(*) AS clusters,
                   count(*) FILTER (WHERE cross_infra) AS cross_infra,
                   max(n_asns) AS max_asns
            FROM read_parquet('{comp_clusters_path}')
        """).fetchone()
        composite_summary.update(
            {"clusters": c[0], "cross_infra": c[1], "max_asns": c[2]})
        composite_cross_rows = con.execute(f"""
            SELECT core_hash, tier, n_ips, n_asns, n_cidrs, n_countries,
                   total_packets, span_hours, present, dom_proto, rep_port,
                   seq_chain, sample_asns
            FROM read_parquet('{comp_clusters_path}')
            WHERE cross_infra = TRUE AND seq_chain NOT LIKE 'ICMP/8.0%'
            ORDER BY n_asns DESC, n_ips DESC, total_packets DESC
            LIMIT 30
        """).fetchall()

    # ---- v2.9: campaignmigration - fingerprint rotation across infrastructure ----
    migration_summary: dict = {}
    migration_cohost: list = []
    migration_handoff: list = []
    migration_hosts: list = []
    mig_dir = lib.REPORTS / "campaignmigration"
    mig_collab_path = mig_dir / "isp_collab.parquet"
    mig_hosts_path = mig_dir / "compromised_hosts.parquet"
    mig_path = mig_dir / "migration.parquet"
    if mig_path.exists():
        s = con.execute(f"""
            SELECT count(DISTINCT core_hash) AS campaigns,
                   count(DISTINCT asn) AS asns
            FROM read_parquet('{mig_path}')
        """).fetchone()
        migration_summary = {"campaigns": s[0], "asns": s[1]}
    if mig_hosts_path.exists():
        for cls, n in con.execute(f"""
            SELECT host_class, count(*) FROM read_parquet('{mig_hosts_path}')
            GROUP BY host_class
        """).fetchall():
            migration_summary[f"host_{cls}"] = n
        migration_hosts = con.execute(f"""
            SELECT src_ip, host_class, n_campaigns, active_days, packets,
                   asn, country_iso
            FROM read_parquet('{mig_hosts_path}')
            ORDER BY n_campaigns DESC, active_days DESC, packets DESC
            LIMIT 25
        """).fetchall()
    if mig_collab_path.exists():
        migration_cohost = con.execute(f"""
            SELECT src_asn, src_org, dst_asn, dst_org, shared_campaigns
            FROM read_parquet('{mig_collab_path}') WHERE kind = 'cohost'
            ORDER BY shared_campaigns DESC LIMIT 30
        """).fetchall()
        migration_handoff = con.execute(f"""
            SELECT src_asn, src_org, dst_asn, dst_org, shared_campaigns
            FROM read_parquet('{mig_collab_path}') WHERE kind = 'handoff'
            ORDER BY shared_campaigns DESC LIMIT 25
        """).fetchall()

    # ---- cross-signal problems (deterministic verdicts) ----
    # conclusions/correlate finds the patterns; conclusions/verdict gives
    # each one a fact-based verdict and merges them into problems.  No LLM:
    # the opt-in synthesize narratives are not part of the report.
    problem_rows: list[dict] = []
    verdict_rows: list[dict] = []
    concl_dir = lib.OUTPUT_DIR / "conclusions"
    try:
        if (concl_dir / "problems.parquet").exists():
            problem_rows = pq.read_table(concl_dir / "problems.parquet").to_pylist()
        if (concl_dir / "verdicts.parquet").exists():
            titles = {f["finding_id"]: f["pattern_title"] for f in pq.read_table(
                concl_dir / "findings.parquet",
                columns=["finding_id", "pattern_title"]).to_pylist()}
            verdict_rows = pq.read_table(concl_dir / "verdicts.parquet").to_pylist()
            for r in verdict_rows:
                r["title"] = titles.get(r["finding_id"], r["pattern_id"])
    except Exception as e:
        print(f"[report] could not read verdicts/problems: {e}", file=sys.stderr)

    con.close()

    # ------------------------------------------------------------------
    # Compose the report
    # ------------------------------------------------------------------
    print("[report] composing markdown...", file=sys.stderr)
    md: list[str] = []
    def H(level: int, text: str): md.append(f"\n{'#' * level} {text}\n")
    def P(text: str = ""): md.append(text)

    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    H(1, "SensorGrind_AI - Comprehensive Threat Intelligence Report")
    P(f"_Generated: {now}_  \n_Snapshot: {snap_date}_  \n"
      f"_Corpus span: {first_ts} to {last_ts} ({total_days} active days)_")

    # ---------- 0. TL;DR ----------
    # Multi-AI consensus: the original report buries the lede.  A SOC
    # consumer needs a one-screen answer to "what changed, who's loud,
    # what should I do" *before* the deep dive.  This Section 0 is that
    # screen — every figure here is also expanded in later sections.
    H(2, "0. TL;DR - what a defender needs to know in 60 seconds")
    P("_This is the one-screen executive read.  Every claim below links "
      "to a later section that shows the evidence.  If you only have "
      "60 seconds, this is the section to read._")
    P("")
    crit_n = tier_counts.get("critical", 0)
    high_n = tier_counts.get("high", 0)
    total_t0 = sum(tier_counts.values()) or 1
    P(f"### Headline\n")
    P(f"- **{total_packets:,} packets** from **{total_ips:,} unique IPs** "
      f"over **{total_days:,} active days** ({first_ts} to {last_ts}).")
    P(f"- **{crit_n:,} critical** + **{high_n:,} high-risk** sources "
      f"({(crit_n + high_n) / total_t0:.1%} of the population) — "
      f"see Section 1 (risk tiers).")
    if drift_rows:
        sig_drift0 = sum(1 for r in drift_rows if r[5])
        if sig_drift0:
            P(f"- **Threat landscape SHIFTED**: {sig_drift0} feature(s) "
              f"show significant drift between the recent window and the "
              f"60-day baseline — retrain indicated. See Section 12.")
        else:
            P("- Threat landscape is **stable** — no significant feature "
              "drift detected. See Section 12.")
    if auto_rules:
        P(f"- **{len(auto_rules):,} new behavioral rules** auto-promoted "
          f"this run — review and deploy. See Section 13.")
    act_probs = [p for p in problem_rows if p["verdict"] in verdict.ACT_VERDICTS]
    if problem_rows:
        n_benign = sum(p["finding_count"] for p in problem_rows
                       if p["verdict"] in ("benign_p2p", "research_scanner"))
        n_uncl = sum(p["finding_count"] for p in problem_rows
                     if p["verdict"] == "unclassified")
        P(f"- **{len(verdict_rows)} cross-signal findings → "
          f"{len(problem_rows)} problems**: **{len(act_probs)} need action**, "
          f"{n_benign} findings are benign (BitTorrent peers, known scanners), "
          f"{n_uncl} are unclassified — see Section 0.5.")
    P("")
    if risk_top:
        P("### Top 5 threat IPs (by composite risk score)\n")
        P("| rank | src_ip | risk | tier | ml_score | rationale |")
        P("| --- | --- | --- | --- | --- | --- |")
        for i, r in enumerate(risk_top[:5], 1):
            rat = (r[4] or "")[:80].replace("|", "\\|")
            P(f"| {i} | `{r[0]}` | {r[1]:.1f} | {r[2]} | "
              f"{r[3]:.2f} | {rat} |")
        P("")
    if actor_communities:
        P("### Top 5 actor communities (by member count)\n")
        P("_Behavioral clusters of cooperating source IPs.  When "
          "`originintel` has profiled the community, the AI-suggested "
          "name + actor class are shown — treat as a hypothesis, not "
          "attribution.  See Section 17 (Actor Atlas) for full profiles._\n")
        P("| rank | community | size | avg_risk | actor_class | confidence |")
        P("| --- | --- | --- | --- | --- | --- |")
        for i, r in enumerate(actor_communities[:5], 1):
            cid0 = int(r[0])
            mc0 = int(r[1])
            ar0 = float(r[2] or 0)
            prof0 = actor_profiles_map.get(cid0, {})
            name0 = prof0.get("candidate_name", f"community-{cid0}") \
                or f"community-{cid0}"
            cls0 = prof0.get("likely_actor_class", "(unprofiled)") \
                or "(unprofiled)"
            conf0 = prof0.get("confidence", "—") or "—"
            P(f"| {i} | {name0} (#{cid0}) | {mc0:,} | {ar0:.1f} | "
              f"{cls0} | {conf0} |")
        P("")
    P("### Recommended next steps\n")
    rec_steps: list[str] = []
    for p in act_probs:
        rec_steps.append(
            f"**{p['verdict']}: {p['target']}** "
            f"(sources: {verdict.sources_text(p)}) — {p['action']}")
    if crit_n:
        rec_steps.append(
            f"Pull the **{crit_n:,} critical-tier IPs** from Section 1 "
            "into the blocklist / detection pipeline."
        )
    if drift_rows and any(r[5] for r in drift_rows):
        rec_steps.append(
            "Investigate the drifted features in Section 12 — the "
            "current detector calibration may be drifting from ground "
            "truth.  Retrain `threat_classifier` and `actor_clusterer`."
        )
    if auto_rules:
        rec_steps.append(
            f"Review the {len(auto_rules):,} auto-promoted rules in "
            "Section 13 before deploying them to production sensors."
        )
    if actor_communities and actor_profiles_map:
        rec_steps.append(
            "Cross-check the top actor communities in Section 17 "
            "against existing threat-intel feeds — anything new is a "
            "candidate for proactive hunting."
        )
    if not rec_steps:
        rec_steps.append(
            "No urgent action items — sensor activity is consistent "
            "with the historical baseline this window."
        )
    for s in rec_steps:
        P(f"- {s}")
    P("")
    P("---")

    # ---------- 0.5 Cross-Signal Problems ----------
    # Findings from the correlator with a deterministic verdict each
    # (conclusions/verdict.py), merged into problems by (verdict, target).
    # Every verdict names the rule and the facts that made it fire, so the
    # same corpus always gives the same table.
    H(2, "0.5 Cross-Signal Problems")
    if problem_rows:
        P("**What this section shows:** the correlator's findings, each with a "
          "verdict from fixed rules over measured facts (L7 protocol share, "
          "known-scanner share, botnet payloads, bulletproof hosting, HTTP "
          "credentials).  Findings with the same verdict and target are one "
          "problem.  `sources` counts distinct member IPs; `of >= N` shows the "
          "full population when a finding keeps only a sample.  Rules: "
          "`src/conclusions/verdict.py`.  No rule fired → `unclassified`.")
        P("")
        P("### Problems\n")
        for line in verdict.problem_table(problem_rows):
            P(line)
        P("")
        P("### Finding index\n")
        P("| verdict | finding | sources | rule | why |")
        P("| --- | --- | ---: | --- | --- |")
        vorder = {v: i for i, v in enumerate(verdict.VERDICT_ORDER)}
        for r in sorted(verdict_rows, key=lambda r: (
                vorder[r["verdict"]], r["target"], r["finding_id"])):
            cells = [r["verdict"], r["title"], f"{r['n_members']:,}",
                     r["rule_id"], r["why"] + (f" ({r['note']})" if r["note"] else "")]
            P("| " + " | ".join(str(c).replace("|", "\\|") for c in cells) + " |")
        P("")
    else:
        P("_No verdicts this run.  Run `python src/evolve.py correlate verdict` "
          "to populate this section._")
    P("")
    P("---")

    # ---------- 1. Executive Summary ----------
    H(2, "1. Executive Summary")
    P("**What this section shows:** the bottom-line totals for the whole "
      "corpus and a snapshot of how many IPs ended up in each risk tier.  "
      "It's the answer to *'in one screen, what is this sensor seeing?'*  "
      "Every figure below is derived from the parser's Parquet tables and "
      "the v2/v2.1 ML/risk pipeline.")
    P("")
    P("### Top-line metrics\n")
    P("_Raw aggregates over the full corpus. 'Distinct payload blobs' is "
      "after SHA-256 deduplication. 'L7-classified events' counts only "
      "packets where the parser was able to identify a layer-7 protocol "
      "(HTTP/TLS/SSH/RDP/etc.); the rest are still in `packets` but show "
      "up as `l7_proto=unknown`._")
    P("")
    P("| metric | value |\n| --- | --- |")
    P(f"| total packets | {total_packets:,} |")
    P(f"| total bytes  | {total_bytes:,} |")
    P(f"| unique source IPs | {total_ips:,} |")
    P(f"| distinct payload blobs | {blob_count:,} |")
    P(f"| L7-classified events | {l7_count:,} |")
    P(f"| IOCs extracted | {ioc_count:,} |")
    P(f"| active days in corpus | {total_days:,} |")

    outages = sensor_outages()
    P("\n### Sensor outages\n")
    P("_Each run of whole UTC days with no packets at all - the sensor was "
      "off, unplugged, or its log was lost.  Every rate, baseline and "
      "first-seen figure in this report has a hole here; do not read a "
      "drop in activity across these dates as attacker behavior.  Gaps "
      "shorter than a day are masked per detector by `sensormask`._")
    P("")
    if outages:
        P(f"**{len(outages):,} outages, {sum(n for *_, n in outages):,} "
          "days with no packets.**\n")
        P("| first day | last day | days |\n| --- | --- | ---: |")
        for a, b, n in outages:
            P(f"| {a} | {b} | {n:,} |")
    else:
        P("_No whole-day outages in the corpus._")

    if tier_counts:
        P("\n### Risk tier distribution\n")
        P("_Composite risk score buckets all sources into five tiers "
          "(critical >=80, high 60-80, medium 40-60, low 20-40, info <20).  "
          "Score combines the ML threat probability (35% weight) with "
          "persistence, breadth, exploit signal, botnet confirmation, "
          "infrastructure class, and ECOD anomaly score; benign-tagged "
          "scanners get a -40 offset.  Read the pie below as 'how heavy "
          "is the tail of true threats vs the long flat info-tier?'_")
        P("")
        pie_data = [(t, tier_counts.get(t, 0))
                    for t in ("critical", "high", "medium", "low", "info")]
        P(mermaid_pie("IPs by risk tier", pie_data))
        P("")
        total_t = sum(tier_counts.values()) or 1
        P("| tier | count | share |\n| --- | --- | --- |")
        for t in ("critical", "high", "medium", "low", "info"):
            v = tier_counts.get(t, 0)
            P(f"| {t} | {v:,} | {v/total_t:.1%} |")

    H(3, "Key findings")
    findings: list[str] = []
    if "critical" in tier_counts:
        findings.append(f"**{tier_counts['critical']:,} IPs** classified as **critical-tier threats** "
                        f"({tier_counts['critical']/total_t:.1%} of the population).")
    if chain_rows:
        rpdbc = next((r for r in chain_rows if r[0] == "RPDBC"), None)
        if rpdbc:
            findings.append(f"**{rpdbc[1]:,} IPs** progress through the full 6-stage attack chain "
                            f"(RPDBC) with an average dwell time of **{rpdbc[2]:.0f} days**.")
    if wave_rows:
        biggest = max(wave_rows, key=lambda r: r[0])
        findings.append(f"Largest coordinated payload wave: **{biggest[0]:,} distinct IPs** "
                        f"sending the same payload over {biggest[3]:.0f} minutes.")
    if drift_rows:
        sig_drift = sum(1 for r in drift_rows if r[5])
        findings.append(f"**{sig_drift} of {len(drift_rows)} features** show significant drift "
                        f"between the last 7 days and prior 60-day baseline - retraining indicated.")
    if auto_rules:
        findings.append(f"**{len(auto_rules):,} behavioral rules** auto-promoted to the rule library "
                        f"this run, plus **{len(queued_rules):,}** content-pattern candidates queued for review.")
    if cluster_rows:
        findings.append(f"HDBSCAN discovered **{len(cluster_rows):,}+ operator clusters**; the system "
                        f"independently rediscovered known scanning organizations (Censys, ONYPHE, Driftnet).")
    for f in findings:
        P(f"- {f}")

    # ---------- 2. Volumetric Analysis ----------
    H(2, "2. Volumetric Analysis")
    P("**What this shows:** how much traffic the sensor saw, broken "
      "down by month and by transport/application protocol.  Volume "
      "spikes typically reflect (a) the original 2019 dataset baseline, "
      "(b) major worm/botnet propagation events, and (c) coordinated "
      "scanning waves visible in the coordination report.  Protocol "
      "mix gives the simplest version of *'what services are being "
      "probed at this sensor?'*")
    if daily:
        months = [str(d[0])[:7] for d in daily]
        pkt_vals = [int(d[1]) for d in daily]
        ip_vals = [int(d[2]) for d in daily]
        if len(months) > 30:
            stride = len(months) // 30
            months = months[::stride]
            pkt_vals = pkt_vals[::stride]
            ip_vals = ip_vals[::stride]
        H(3, "Monthly packet volume")
        P("_Packets ingested per calendar month.  Watch for sudden spikes "
          "(campaign launches) vs sustained shifts (population change)._")
        P("")
        P(smart_line("Packets per month", months, pkt_vals, "packets"))
        H(3, "Monthly unique source IPs")
        P("_Number of distinct source IPs seen each month.  Decoupling "
          "this from raw packet count separates *'fewer attackers hitting "
          "harder'* from *'more attackers each doing a little'*._")
        P("")
        P(smart_line("Distinct src IPs per month", months, ip_vals, "ips"))

    H(3, "Protocol mix")
    P("_L4 transport breakdown over the whole corpus.  >99% TCP is "
      "expected for a sensor that emulates TCP services; UDP and ICMP "
      "slices reveal scanning/recon traffic._")
    P("")
    if proto_mix:
        P(mermaid_pie("Layer-4 protocol", [(k, v) for k, v in proto_mix.items()]))

    H(3, "L7 protocol mix (classified events)")
    P("_Distribution across the application-layer protocols the parser "
      "recognized in payloads (HTTP, TLS, SSH, RDP, BitTorrent, MongoDB, "
      "etc.).  Excludes the much larger pool of `l7_proto=unknown` "
      "payloads.  HTTP and TLS dominance is normal for an internet-facing "
      "honeypot._")
    P("")
    if l7_mix:
        top_l7 = sorted(l7_mix.items(), key=lambda x: x[1], reverse=True)[:10]
        P(mermaid_pie("L7 protocol", top_l7))

    # ---------- 3. Geographic & Infrastructure ----------
    H(2, "3. Geographic & Infrastructure Analysis")
    P("**What this shows:** where attack traffic comes from and which "
      "hosting providers carry it.  The top-country bar chart is the "
      "geographic distribution; the ASN-org table breaks that down by "
      "provider so you can spot bulletproof-hosting concentration "
      "(MEVSPACE, Skynet, Tamatiya, IPTransit) vs cloud providers "
      "(AWS, GCP, DigitalOcean) vs residential ISPs.  Benign-org "
      "breakdown shows which IPs were identified by the benignfilter "
      "as known research scanners (Shodan, Censys, Driftnet, etc.) so "
      "you can subtract that background.")
    if geo_rows:
        H(3, "Top 20 source countries by IP count")
        P("_Sorted by distinct attacker IP count, not packet volume.  "
          "Big absolute numbers reflect population size of the country's "
          "internet user base; comparing this to IP-per-capita rates "
          "is left to the reader._")
        P("")
        P(smart_bar("Top countries",
                              [r[0] for r in geo_rows],
                              [r[1] for r in geo_rows],
                              y_title="ips"))
    if asn_rows:
        H(3, "Top 20 ASNs by packet volume")
        P("_Sorted by total packets, not IP count - so a single noisy "
          "actor with thousands of IPs can dominate.  Look for "
          "well-known bulletproof providers (MEVSPACE, IPTransit, "
          "Skynet, Tamatiya) clustering near the top - that signals "
          "a hostile-hosting concentration worth blocking._")
        P("")
        P("| asn_org | ips | pkts |\n| --- | --- | --- |")
        for org, n_ips, n_pkts in asn_rows:
            org_t = (org or "")[:60].replace("|", "\\|")
            P(f"| {org_t} | {n_ips:,} | {n_pkts:,} |")

    if benign_org_counts:
        H(3, "Benign vs flagged scanner organizations")
        P("_Distribution of the IPs that benignfilter classified as "
          "known research/scanning organizations.  Lets you size how "
          "much 'noise' the benign-filter is removing before downstream "
          "threat detection looks at the remainder._")
        P("")
        P(mermaid_pie("Known-benign IPs by org",
                      [(r[0], r[1]) for r in benign_org_counts[:10]]))

    # ---------- 4. Risk Stratification ----------
    H(2, "4. Risk Stratification")
    P("**What this shows:** the shape of the composite risk distribution "
      "and the ML threat-classifier probability distribution.  A "
      "well-calibrated classifier produces a U-shape (heavy at 0 and 1, "
      "thin in the middle); the bimodal histogram you see here is "
      "consistent with the model AUC=0.997 - the labels separate cleanly "
      "into clearly-benign and clearly-malicious cohorts with a small "
      "ambiguous middle.  The top-25 IP list below is the actionable "
      "output: sorted by composite score, with per-IP rationale showing "
      "which signal(s) drove the score.")
    if risk_score_values:
        H(3, "Composite risk score distribution (50k sample)")
        P("_Percentile table summarizes the score distribution; the "
          "histogram below it shows the shape.  A heavy right tail "
          "(p99 well above p75) means a small subset of IPs carries "
          "almost all the risk - typical for honeypot data, since "
          "real attackers are a fraction of the unique-IP count._")
        P("")
        P(percentile_table(risk_score_values))
        P("")
        P(mermaid_histogram("Composite risk score histogram",
                            risk_score_values, n_bins=10,
                            y_title="ips"))
    if ml_score_values:
        H(3, "ML threat probability distribution (50k sample)")
        P("_The raw output of the LightGBM threat_classifier model.  "
          "A bimodal distribution (heavy at 0 and 1, thin in the middle) "
          "is what a well-calibrated binary classifier on cleanly-"
          "separable labels produces and is consistent with the "
          "AUC=0.997 / AP=0.999 the training reported.  The middle "
          "bins are the ambiguous cohort worth manually labeling for "
          "active-learning iterations._")
        P("")
        P(percentile_table(ml_score_values))
        P("")
        P(mermaid_histogram("ML threat probability histogram",
                            ml_score_values, n_bins=10,
                            y_title="ips"))

    if risk_top:
        H(3, "Top 25 highest-risk IPs")
        P("_The 25 highest-composite-score IPs in the corpus.  Each "
          "row's `rationale` field lists the signals that drove the "
          "score - `ML=0.98` (model confidence), `botnet=mozi` (family "
          "confirmation), `uris=145` (number of distinct probe URIs), "
          "`persist=127d` (active days), `infra=bulletproof` "
          "(ASN reputation).  Combine with the per-IP dossiers under "
          "`output/risk/dossiers/` for the full evidence trail._")
        P("")
        P("| rank | src_ip | tier | score | ml | rationale |")
        P("| --- | --- | --- | --- | --- | --- |")
        for i, r in enumerate(risk_top, 1):
            ip, score, tier, ml, rat = r
            P(f"| {i} | {ip} | {tier} | {score:.1f} | {ml:.2f} | {rat} |")

    # ---------- 5. Attack Chain Analysis ----------
    H(2, "5. Attack Chain Analysis")
    P("Six-stage lifecycle taxonomy:")
    P("")
    P("| stage | meaning |")
    P("| --- | --- |")
    P("| R | Recon (SYN sweep across 10+ distinct ports) |")
    P("| P | Probe (any L7 protocol handshake / banner) |")
    P("| X | Exploit (HTTP URI matched a known probesigs CVE/RCE tag) |")
    P("| C | Credentials (mstshash cookie or user:pass IOC) |")
    P("| D | Dropper (wget/tftp/curl URL or busybox command IOC) |")
    P("| B | Botnet payload (classified into a known family by botnetcls) |")

    # ---- 5a. Stage prevalence (how many attackers ever touch this stage) ----
    if chain_rows:
        stage_count = {s: 0 for s in "RPXCDB"}
        for chain, n, *_ in chain_rows:
            seen = set(chain or "")
            for s in seen:
                if s in stage_count:
                    stage_count[s] += n
        H(3, "Stage prevalence (top chain shapes only)")
        P("_Number of IPs whose attack chain visits each stage._")
        P("")
        P(smart_bar(
            "IPs visiting each stage",
            list(stage_count.keys()),
            list(stage_count.values()),
            y_title="ips",
        ))

    # ---- 5b. Real transition graph from length-2 ngrams ----
    if transitions:
        # Sankey-beta rejects cycles; filter to the canonical forward direction.
        order = {"R": 0, "P": 1, "X": 2, "C": 3, "D": 4, "B": 5}
        forward = [(g[0], g[1], cnt) for g, cnt, _ in
                   ((row[0], row[1], row[2]) for row in transitions)
                   if len(g) == 2 and order.get(g[0], 9) < order.get(g[1], 9)]
        forward = forward[:14]  # top-N for readability

        if forward:
            H(3, "Observed stage transitions (Sankey of length-2 n-grams)")
            P("_Edge widths are proportional to the number of IPs that took "
              "that transition; only forward-direction transitions are shown "
              "(Mermaid sankey-beta does not allow cycles)._")
            P("")
            P(mermaid_sankey(forward))

        H(3, "All observed transitions (including backward / unusual edges)")
        P("| transition | ip_count | support |")
        P("| --- | --- | --- |")
        for ngram, n, pct in transitions[:20]:
            arrow = f"{ngram[0]} -> {ngram[1]}"
            P(f"| {arrow} | {n:,} | {pct:.1%} |")

    if chain_rows:
        H(3, "Top observed chain shapes")
        P("| chain | ips | avg_span_d | avg_risk |")
        P("| --- | --- | --- | --- |")
        for r in chain_rows:
            P(f"| {r[0]} | {r[1]:,} | {r[2]:.1f} | {r[3]:.1f} |")

        full = next((r for r in chain_rows if r[0] == "RPDBC"), None)
        if full:
            H(3, f"Full 6-stage chain sequence diagram (cohort: {full[1]:,} IPs that completed RPDBC)")
            P("_This is the chain shape followed specifically by the RPDBC cohort "
              "- a small, high-risk minority. The majority of attackers follow "
              "shorter shapes; see the Sankey above for the population-level flow._")
            P("")
            P(mermaid_sequence(
                ["Attacker", "Sensor", "C2"],
                [("Attacker", "Sensor", "R: SYN scan many ports"),
                 ("Attacker", "Sensor", "P: L7 banner probe"),
                 ("Attacker", "Sensor", "X: CVE/exploit URI"),
                 ("Attacker", "Sensor", "C: credential stuffing"),
                 ("Attacker", "Sensor", "D: dropper URL fetched"),
                 ("Sensor", "C2", "B: payload check-in")]))

    if seq_rows:
        H(3, "Top n-gram transitions (all lengths)")
        P("_Same data as the length-2 sankey above but extended to "
          "include 3- and 4-letter subsequences too.  Reading top to "
          "bottom shows you the dominant short transitions first, then "
          "the longer playbooks.  Use this to spot multi-step patterns "
          "the sankey can't visualize (e.g. RPDB - the four-step full "
          "infection chain)._")
        P("")
        P("| ngram | length | ips | support |")
        P("| --- | --- | --- | --- |")
        for r in seq_rows:
            P(f"| {r[0]} | {r[1]} | {r[2]:,} | {r[3]:.1%} |")

    # ---------- 6. Coordinated Activity / Campaigns ----------
    H(2, "6. Coordinated Activity - Campaign Onsets & Arrival Bursts")
    P("**What this shows:** the *leading edge* of attack and scan "
      "campaigns visible at the sensor.  A campaign here is a single "
      "payload SHA-256 sent by many distinct IPs where the bulk of "
      "those senders first-touched the sensor in a focused slice of "
      "time, rather than spread evenly across the multi-year corpus.  "
      "We compute the per-IP first-arrival distribution per payload, "
      "extract the p5 (launch), p25, p50, p75, p95 (decay), and the "
      "single busiest day (peak), then rank by density_score = "
      "ip_count * (corpus_span_days / burst_window_days).  Always-on "
      "background payloads (whose senders span the whole corpus) are "
      "filtered out.  Arrival bursts capture the complementary view: "
      "minute-buckets where the rate of new-to-this-sensor IPs spiked "
      "far above baseline.")
    if campaign_rows:
        # ---- per-month launch histogram ----
        if campaign_launches_by_month:
            H(3, "New campaign launches per month (campaign p5 \"launch_ts\")")
            P("_Counts the number of distinct campaign payloads whose "
              "p5 first-arrival lands in each month.  Spikes mark "
              "moments when many fresh operators / fresh exploits "
              "started hitting the sensor; gaps mark quiet periods._")
            P("")
            P(smart_bar(
                "Campaign launches",
                [ym for ym, _ in campaign_launches_by_month],
                [float(n) for _, n in campaign_launches_by_month],
                "month", "new campaigns",
            ))

        # ---- gantt of top 20 campaign lifespans ----
        gantt_items = []
        for i, r in enumerate(campaign_rows[:20]):
            (n, launch_ts, peak_day, decay_ts, burst_d,
             peak_n, l7p, _samples, _density) = r
            if launch_ts is None or decay_ts is None:
                continue
            section = f"Top 20 campaigns"
            task = (f"#{i+1} {n}ips/{burst_d:.0f}d "
                    f"{l7p or 'unknown'}")
            gantt_items.append((
                section, task,
                launch_ts.date().isoformat() if hasattr(launch_ts, "date") else str(launch_ts)[:10],
                decay_ts.date().isoformat()  if hasattr(decay_ts, "date")  else str(decay_ts)[:10],
            ))
        if gantt_items:
            H(3, "Top 20 campaign lifespans (Gantt: launch_ts -> decay_ts)")
            P("_Each bar runs from the p5 (launch) of per-IP "
              "first-arrivals to the p95 (decay).  Short bars = "
              "tightly clustered campaigns; longer bars = slow-rolling "
              "campaigns that nevertheless concentrated within their "
              "burst window, not the whole corpus.  X-axis is dd/mm/yyyy, "
              "monthly gridlines._")
            P("")
            VISUALS_DIR.mkdir(parents=True, exist_ok=True)
            P(svg_gantt_chart(
                "Top 20 campaign lifespans",
                gantt_items,
                VISUALS_DIR / "top20_campaign_lifespans.svg",
            ))

        # ---- top 50 table ----
        H(3, f"Top 50 campaigns by density_score ({len(campaign_rows)} shown)")
        P("_`burst_d` = days between p5 (launch) and p95 (decay) of per-IP "
          "first-arrivals.  `peak_d_ips` = number of new senders that "
          "first-touched the sensor on the campaign's busiest day.  "
          "`density_score` rewards both large operator counts and tight "
          "burst windows._")
        P("")
        P("| # | launch_ts | peak_day | decay_ts | burst_d | ip_count | "
          "peak_d_ips | l7 | density | sample_ips |")
        P("| ---: | --- | --- | --- | ---: | ---: | ---: | --- | ---: | --- |")
        for i, r in enumerate(campaign_rows, 1):
            (n, launch_ts, peak_day, decay_ts, burst_d, peak_n, l7p,
             samples, density) = r
            samples_short = (samples or "")[:80].replace("|", "\\|")
            launch_s = (launch_ts.strftime("%Y-%m-%d %H:%M")
                        if hasattr(launch_ts, "strftime") else str(launch_ts)[:16])
            peak_s = (peak_day.strftime("%Y-%m-%d")
                      if hasattr(peak_day, "strftime") else str(peak_day)[:10])
            decay_s = (decay_ts.strftime("%Y-%m-%d %H:%M")
                       if hasattr(decay_ts, "strftime") else str(decay_ts)[:16])
            P(f"| {i} | {launch_s} | {peak_s} | {decay_s} | "
              f"{burst_d:.1f} | {n:,} | {peak_n:,} | "
              f"{l7p or 'unknown'} | {density:,.0f} | {samples_short} |")

    if burst_rows:
        H(3, "Top 15 arrival bursts (sudden floods of new IPs)")
        P("_Minute-resolution buckets where the count of brand-new "
          "(never-seen-before) source IPs spiked above the corpus "
          "median.  `x_baseline` = ratio vs the median minute.  "
          "5x+ baseline is the threshold for inclusion - large ratios "
          "indicate coordinated campaign launches or worm propagation "
          "moments._")
        P("")
        P("| bucket_start | new_ips | x_baseline |")
        P("| --- | --- | --- |")
        for b, n, r in burst_rows:
            P(f"| {b} | {n:,} | {r:.1f}x |")

    # ---------- 7. Pattern & Rule Mining ----------
    H(2, "7. Pattern & Rule Mining")
    P("**What this shows:** the unsupervised side of the learn-and-"
      "evolve loop.  FP-Growth mines frequent co-occurring behavioral "
      "tokens (port:N, asn:N, cc:XX, l7:proto, ua:hash, uri:tag, "
      "bot:family) across IPs.  Itemsets with >=85% threat-purity over "
      ">=50 IPs are *auto-promoted* if they contain only behavioral "
      "tokens (low blast-radius if wrong), or *queued* for human "
      "review if they contain content tokens (UA strings, URIs, "
      "botnet families) where a misclassification has higher impact.")
    if auto_rules:
        H(3, f"Auto-promoted behavioral rules ({len(auto_rules)} shown)")
        P("_Itemsets that contain only port/ASN/country/L7 tokens and "
          "satisfy ip_count >= 50 and threat_pct >= 85%.  These can be "
          "wired directly into a detection feed because misfires only "
          "ever flag *behavioral* patterns - the worst case is "
          "over-blocking a port combination, not mis-attributing a "
          "specific tool._")
        P("")
        P("| rule_id | itemset | ips | threat_pct | avg_risk |")
        P("| --- | --- | --- | --- | --- |")
        for r in auto_rules:
            P(f"| {r[0]} | {r[1]} | {r[2]:,} | {r[3]:.1%} | {r[4]:.1f} |")

    if queued_rules:
        H(3, f"Content rules queued for human review ({len(queued_rules)} shown)")
        P("_Same purity bar as the auto-promoted set, but contains UA "
          "hashes, URIs, or botnet family names - content tokens whose "
          "misclassification has higher blast radius.  The "
          "`sample_ips` column lets you sanity-check a candidate by "
          "spot-reading the matching IPs' dossiers before promoting._")
        P("")
        P("| rule_id | itemset | ips | threat_pct | sample_ips |")
        P("| --- | --- | --- | --- | --- |")
        for r in queued_rules:
            P(f"| {r[0]} | {r[1]} | {r[2]:,} | {r[3]:.1%} | {r[5]} |")

    # ---------- 8. Botnet & Malware ----------
    H(2, "8. Botnet & Malware Activity")
    P("**What this shows:** distribution of payloads classified into "
      "known IoT-botnet families by `botnetcls` (Mirai, Mozi, Hajime, "
      "Tsunami/Kaiten, LZRD, generic IRC-bot, generic RCE-scanner).  "
      "Family markers are matched as word-bounded signatures against payload "
      "strings — Mozi requires the `Mozi.m`/`Mozi.a` dropper marker, not the "
      "substring inside `Mozilla` user-agents (a prior signature bug labeled "
      "~356K browser/zgrab probes as Mozi; now corrected).  Tied to a payload "
      "SHA-256, each row tells you which exact byte pattern is the family "
      "marker.")
    if fam_rows:
        H(3, "Family distribution (classified payload blobs)")
        P("_Distinct payload blob count per family, not packet count.  "
          "A small number of family-specific payload SHA-256s can "
          "appear in millions of packets if the family is widely "
          "deployed.  Cross-reference with section 18 (landscape) for "
          "per-month family trajectories - extinctions and emergences "
          "show up there._")
        P("")
        P(mermaid_pie("Botnet/malware family",
                      [(r[0], r[1]) for r in fam_rows]))
        P("\n| family | blobs |\n| --- | --- |")
        for fam, n in fam_rows:
            P(f"| {fam} | {n:,} |")

    # ---------- 9. Exploit Probes & CVE Activity ----------
    H(2, "9. Exploit Probes & CVE Activity")
    P("**What this shows:** HTTP URIs in the IOC stream that match a "
      "known exploit-probe signature (Log4Shell, ProxyShell, GPON RCE, "
      "FortiGate path traversal, PHPUnit RCE, AWS-creds disclosure, "
      "etc.) plus tagged signatures (Tomcat manager, Solr admin, "
      "Jenkins, phpMyAdmin, etc.).  The cross-modal lag table beneath "
      "lists pairs of activity series whose daily counts correlate "
      "strongly at a non-zero day-lag - useful for spotting *'X "
      "campaign reliably precedes Y campaign by L days'* relationships.")
    if probe_rows:
        H(3, "Probe tag distribution (URIs matched)")
        P("_Count of distinct HTTP URIs that matched each probesigs "
          "regex.  Generic categories (ENV_DISCLOSURE, RCE_PROBE, "
          "CGI_PROBE, PHPMYADMIN) typically dominate because their "
          "regexes are broad; the specific `CVE-YYYY-NNNNN` tags are "
          "narrower but more attributable - those are the ones to "
          "cross-correlate with vendor advisories._")
        P("")
        P(smart_bar("Top probe tags",
                              [r[0] for r in probe_rows[:15]],
                              [r[1] for r in probe_rows[:15]],
                              y_title="distinct URIs"))
        P("\n| tag | count |\n| --- | --- |")
        for tag, c in probe_rows:
            P(f"| {tag} | {c:,} |")

    if lag_rows:
        H(3, "Top cross-modal lag relationships")
        P("_Pairs of daily activity series whose counts correlate "
          "strongly at a non-zero day-lag.  Positive `lag_days` means "
          "series A precedes series B by that many days "
          "(e.g. `API_ENUM -> AWS_CREDS, +2d` = API-enumeration probes "
          "appear two days before AWS-credential-disclosure probes).  "
          "Useful for spotting staged-attack relationships and "
          "vulnerability-disclosure-to-exploitation timelines._")
        P("")
        P("| series_a | series_b | lag_days | correlation |")
        P("| --- | --- | --- | --- |")
        for r in lag_rows:
            P(f"| {r[0]} | {r[1]} | {r[2]:+d} | {r[3]:+.3f} |")

    # ---------- 10. Operator Clustering ----------
    H(2, "10. Operator Clustering (HDBSCAN)")
    P("**What this shows:** HDBSCAN clusters of source IPs based on "
      "their 35-feature behavioral vectors (volumetric, protocol mix, "
      "TCP fingerprint, port targeting, payload patterns, timing, IOC "
      "counts).  Each non-noise cluster is a *behavioral group* - IPs "
      "that look identical even though they may be on different ASNs.  "
      "When the model rediscovers known scanning organizations "
      "(Censys, ONYPHE, Driftnet) as tight clusters it's evidence the "
      "feature set captures the right signal.  When a cluster is "
      "100% botnet-tagged with high port-count, it's a tool "
      "fingerprint for a specific operator.")
    if cluster_rows:
        P(f"_{len(cluster_rows)} clusters shown. Each cluster = IPs "
          "with near-identical behavioral signature.  Read "
          "`benign_pct` and `botnet_pct` together: 100% benign + low "
          "ports = research scanner cluster; 100% botnet + high "
          "ports = active operator group; both low = unclassified "
          "behavioral cohort worth investigating._")
        P("")
        P("| cluster | size | country | asn_org | avg_ports | benign_pct | botnet_pct |")
        P("| --- | --- | --- | --- | --- | --- | --- |")
        for r in cluster_rows:
            cid, size, cc, asn, ports, _, b_pct, bot_pct, _ = r
            P(f"| {cid} | {size:,} | {cc} | {(asn or '')[:30]} | "
              f"{ports:.0f} | {b_pct:.0%} | {bot_pct:.0%} |")

    # ---------- 11. Temporal Patterns ----------
    H(2, "11. Temporal Patterns")
    P("**What this shows:** hour-of-day x day-of-week heatmap of total "
      "packet volume.  A perfectly flat heatmap means the attacker "
      "population is dominated by automated 24/7 scanners.  Real "
      "honeypot data shows a clear weekly/diurnal *bias toward Sunday/"
      "Friday and toward UTC 14:00-16:00* because the heavy-hitter "
      "long-running botnet IPs over-represent there - a useful tell.  "
      "Hover any cell in the HTML version for the exact packet count.")
    if heat_grid:
        H(3, "Hour-of-day x Day-of-week activity heatmap")
        dow_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        matrix = []
        for h in range(24):
            row = [heat_grid.get((d, h), 0) for d in range(7)]
            matrix.append(row)
        row_labels = [f"{h:02d}h" for h in range(24)]
        VISUALS_DIR.mkdir(parents=True, exist_ok=True)
        svg_path = VISUALS_DIR / "workhours_heatmap.svg"
        P(svg_heatmap(matrix, row_labels, dow_names, svg_path,
                      title="Packets per (hour-UTC, day-of-week)"))

    # ---------- 12. ML Model Performance & Drift ----------
    H(2, "12. ML Model Performance & Drift")
    P("**What this shows:** model registry and feature drift detector.  "
      "Each model entry lists its training metrics and the feature "
      "set version it was trained on, so you can correlate "
      "predictions back to the exact features that produced them.  "
      "The drift table runs a two-sample Kolmogorov-Smirnov test "
      "between the most recent 7 days of activity and the preceding "
      "60-day baseline; large KS statistic + small p-value mean the "
      "underlying attacker population has shifted and the threat "
      "classifier should be retrained.")
    if registry:
        H(3, "Model registry")
        P("_Each row is the currently-deployed version of a named model.  "
          "`feature_set` tells you which feature-snapshot version the "
          "model was trained on; if you bump the feature schema you "
          "must retrain or risk silent feature-name mismatch.  AUC and "
          "AP are reported on the validation split; n_clusters / "
          "n_noise are for the HDBSCAN actor clusterer._")
        P("")
        P("| model | version | type | feature_set | metrics |")
        P("| --- | --- | --- | --- | --- |")
        for name, entries in registry.items():
            current = next((e for e in entries if e.is_current), entries[-1])
            metrics_summary = ", ".join(
                f"{k}={v:.3f}" if isinstance(v, float) else f"{k}={v}"
                for k, v in current.metrics.items()
                if k in ("auc", "ap", "n_clusters", "n_noise"))
            P(f"| {name} | v{current.version} | {current.model_type} | "
              f"{current.feature_set} | {metrics_summary} |")

    if drift_rows:
        H(3, "Feature drift (last 7 days vs prior 60 days)")
        P("_Two-sample KS test per feature.  Rule of thumb: "
          "`significant = YES` when KS > 0.15 AND p < 0.001.  Read "
          "this table by scanning the `KS` column from top to bottom: "
          "the higher the statistic, the larger the distribution shift "
          "between baseline and recent windows.  When several features "
          "fire YES simultaneously the underlying attacker population "
          "has changed and predictions on recent data are extrapolating "
          "outside the model's training distribution._")
        P("")
        P("| feature | KS | p_value | baseline_mean | recent_mean | significant |")
        P("| --- | --- | --- | --- | --- | --- |")
        for r in drift_rows:
            f, ks, p, bm, rm, sig = r
            P(f"| {f} | {ks:.3f} | {p:.2e} | {bm:.3g} | {rm:.3g} | "
              f"{'YES' if sig else ''} |")
        sig_n = sum(1 for r in drift_rows if r[5])
        if sig_n >= 5:
            P(f"\n> **Recommendation:** {sig_n} features shifted significantly. "
              f"Retrain threat_classifier and re-run pattern mining.")

    # ---------- 13. Survival & Persistence ----------
    H(2, "13. Survival & Persistence")
    P("**What this shows:** lifetime distributions (last_seen - first_seen, "
      "in days) per IP, broken down by cohort: country, infrastructure "
      "class, HDBSCAN cluster, and botnet family.  Cohorts with very "
      "high median lifetime + non-zero `active_pct` are long-term "
      "operators; cohorts with median ~1 day are mostly transient "
      "residential/burst infections.  Direct read for *'who is "
      "persistent and who is throwaway?'*")
    if surv_rows:
        H(3, "Top 30 cohorts by IP count")
        P("_`median_d`/`p75_d`/`p90_d` are days between an IP's first "
          "and last appearance, computed per cohort.  `active_pct` is "
          "the fraction of cohort IPs whose last_seen is within 7 days "
          "of the corpus end (treats them as still-alive, i.e. right-"
          "censored).  Read together: high median + high active_pct = "
          "long-term operator group; low median + low active_pct = "
          "ephemeral cohort.  Cohort kinds: `country` (geo), `infra` "
          "(bulletproof/cloud/residential class), `actor_cluster` "
          "(HDBSCAN id), `botnet_family`._")
        P("")
        P("| kind | cohort | ips | median_d | p75_d | p90_d | active_pct |")
        P("| --- | --- | --- | --- | --- | --- | --- |")
        for r in surv_rows:
            kind, name, n_ips, med, p75, p90, act = r
            P(f"| {kind} | {name} | {n_ips:,} | {med:.1f} | {p75:.1f} | "
              f"{p90:.1f} | {act:.0%} |")

    # ---------- 14. Hostile ASNs (origin) ----------
    H(2, "14. Hostile ASNs - per-network threat profile (asnintel)")
    P("**What this shows:** which Autonomous Systems are predominantly "
      "hosting threats hitting this sensor, what they specialize in, "
      "and an actionable defender grade.  `threat_density` = fraction "
      "of an ASN's IPs at medium+ risk; `cooperation_score` = fraction "
      "of hour-buckets where >=2 of the ASN's IPs were simultaneously "
      "active (proxy for central coordination); `BP` flag means the "
      "AS org name matches a known-bulletproof-hoster keyword.")
    if asn_rows_intel:
        P("")
        P("_Grade scale: `block_asn` = bulk-block the AS; "
          "`monitor_block` = block now, watch collateral; "
          "`watch` = heightened scrutiny; `investigate` = looks like a "
          "coordinated campaign worth a deeper look; `per-ip` = AS too "
          "mixed for AS-level action; `info` = low signal._")
        P("")
        P("| asn | org | cc | ips | threat | density | coop | bp | top_ports | top_fams | top_probes | grade |")
        P("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in asn_rows_intel:
            asn, org, cc, n, t, dens, coop, bp, ports, fams, probes, grade, rec = r
            P(f"| {asn} | {(org or '')[:28]} | {cc} | {n:,} | {t:,} | "
              f"{dens:.0%} | {coop:.2f} | {'BP' if bp else ''} | "
              f"{ports} | {fams} | {probes} | `{grade}` |")
        P("")
        P("_Per-row defender recommendation (full text):_")
        P("")
        P("| asn | recommendation |\n| --- | --- |")
        for r in asn_rows_intel[:15]:
            P(f"| {r[0]} | {r[12]} |")
    else:
        P("")
        P("_No asnintel output yet.  Run `python src/evolve.py asnintel`._")

    # ---------- 15. Compromised CIDR blocks ----------
    H(2, "15. Compromised CIDR Blocks (cidrintel)")
    P("**What this shows:** subnets (/24 and /16) ranked by `block_score`, "
      "a density-weighted IP count that surfaces the most actionable "
      "subnet-level blocks first.  Use this when a per-IP blocklist is "
      "too noisy and an ASN-block is too coarse - whole-subnet blocks "
      "catch fresh sibling IPs from the same compromised range "
      "without manual tracking.")
    if cidr24_rows:
        H(3, "Top 25 hostile /24 blocks")
        P("_The most concentrated /24-sized subnets of threat activity.  "
          "Read the `rec` column for the specific defender action._")
        P("")
        P("| cidr | ips | threats | density | top_asn_org | cc | fam | port | rec |")
        P("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in cidr24_rows:
            cidr, n, t, dens, org, cc, fam, port, rec = r
            P(f"| `{cidr}` | {n:,} | {t:,} | {dens:.0%} | "
              f"{(org or '')[:24]} | {cc} | {fam} | {port} | "
              f"{rec[:48]} |")
    if cidr16_rows:
        H(3, "Top 15 hostile /16 blocks")
        P("_Larger /16 patterns - usually only worth acting on when an "
          "entire registered allocation is mostly hostile.  Typically "
          "informs ASN-level decisions rather than direct blocks._")
        P("")
        P("| cidr | ips | threats | density | top_asn_org | cc | fam | port | rec |")
        P("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in cidr16_rows:
            cidr, n, t, dens, org, cc, fam, port, rec = r
            P(f"| `{cidr}` | {n:,} | {t:,} | {dens:.0%} | "
              f"{(org or '')[:24]} | {cc} | {fam} | {port} | "
              f"{rec[:48]} |")
    if not cidr24_rows and not cidr16_rows:
        P("")
        P("_No cidrintel output yet.  Run `python src/evolve.py cidrintel`._")

    # ---------- 16. Tooling fingerprints ----------
    H(2, "16. Attacker Tooling Fingerprints (tooling)")
    P("**What this shows:** which scanner / exploit framework / botnet "
      "client each attacker IP is running, identified by User-Agent "
      "string substrings, SSH banner substrings, and probesigs CVE/probe "
      "tag matches.  Useful for matching observed activity to threat-intel "
      "tool signatures and for distinguishing 'commodity scanner traffic' "
      "from 'targeted attacker traffic'.")
    if tool_summary:
        H(3, "Tool prevalence (top 20)")
        P("_Number of IPs whose dominant tool maps to each name._")
        P("")
        P(smart_bar("Tools dominating threat IPs",
                    [t for t, _ in tool_summary],
                    [n for _, n in tool_summary],
                    y_title="ips"))
        P("")
        P("| tool | ips |\n| --- | --- |")
        for t, n in tool_summary:
            P(f"| {t} | {n:,} |")
    else:
        P("")
        P("_No tooling output yet.  Run `python src/evolve.py tooling`._")

    # ---------- 17. Actor Atlas ----------
    H(2, "17. Actor Atlas - cooperative-actor communities (actorlink + originintel)")
    P("**What this shows:** the headline output of the origin/"
      "attribution analysis.  Each row is a candidate **actor "
      "community** - a group of source IPs the multi-signal graph "
      "linked together because they share payloads, user-agents, "
      "JA4T fingerprints, probe tags, mstshash cookies, or "
      "synchronized arrival times.  Louvain community detection ran "
      "over the resulting weighted graph; communities with >= 4 members "
      "are surfaced here.  When the AI-driven `originintel` stage has "
      "also run, each community gets a candidate name, actor-class "
      "guess, and defender recommendations.")
    if actor_communities:
        H(3, "Top 15 candidate actor communities")
        P("_Sorted by member count.  Read `shared_signals` to see which "
          "evidence binds the community together (e.g. `payload_sha=12, "
          "ja4t=8, ua_hash=3` = 12 shared-payload edges, 8 shared-"
          "TCP-fingerprint edges, 3 shared-user-agent edges).  Higher "
          "diversity of signals = stronger attribution._")
        P("")
        P("| cid | members | avg_risk | countries | top_asns | shared_signals | tools | targets | sample_ips |")
        P("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in actor_communities:
            cid, mc, avg, cc, asns, sigs, tools, targets, _, _, samples = r
            P(f"| {cid} | {mc:,} | {avg:.1f} | {cc} | {asns} | "
              f"{sigs} | {tools} | {targets} | {samples} |")

        if actor_profiles_map:
            H(3, "AI-generated actor profiles")
            sample_profile = next(iter(actor_profiles_map.values()))
            P(f"_LLM provider: `{sample_profile['provider']}` / "
              f"model: `{sample_profile['model']}`.  For each top "
              "community we feed the evidence bundle to the LLM and "
              "ask for a defender-facing profile: candidate name, "
              "likely actor class, tooling, TTPs, targets, and "
              "concrete defender actions._")
            for r in actor_communities:
                cid = r[0]
                prof = actor_profiles_map.get(int(cid))
                if not prof:
                    continue
                H(4, f"Community {cid} - {prof['candidate_name']}")
                P(f"- **likely actor class:** {prof['likely_actor_class']}")
                P(f"- **confidence:** {prof['confidence']}")
                P(f"- **tooling:** {prof['tooling']}")
                P(f"- **targets:** {prof['targets']}")
                P(f"- **TTPs:** {prof['ttp']}")
                P("")
                P("**Defender actions:**")
                P("")
                for a in (prof["defender_actions"] or "").split(";"):
                    a = a.strip()
                    if a:
                        P(f"- {a}")
                P("")
                P(f"_rationale:_ {prof['rationale']}")
        else:
            P("")
            P("> _AI actor profiles not yet generated.  Run "
              "`python src/evolve.py originintel` to enrich._")
    else:
        P("")
        P("_No actorlink output yet.  Run `python src/evolve.py actorlink`._")

    # ---------- 18. Recommended Actions ----------
    H(2, "18. Recommended Actions")
    recs: list[str] = []
    if drift_rows and sum(1 for r in drift_rows if r[5]) >= 5:
        recs.append("Retrain `threat_classifier` (significant feature drift detected).")
    if auto_rules:
        recs.append(f"Deploy the {len(auto_rules):,} auto-promoted behavioral rules from "
                    "`data/patterns/candidate_rules.parquet`.")
    if queued_rules:
        recs.append(f"Review {len(queued_rules):,} content-rule candidates in the same file "
                    "(disposition='queued') before deploying.")
    if tier_counts.get("critical", 0) > 0:
        recs.append(f"Triage the {tier_counts['critical']:,} critical-tier IPs in "
                    "`data/risk/dossiers/INDEX.md`.")
    if emerge_rows:
        new_ips = next((c for k, c in emerge_rows if k == "src_ip"), 0)
        if new_ips:
            recs.append(f"Investigate the {new_ips:,} new source IPs that emerged in the "
                        "last 7 days (emergence report).")
    if not recs:
        recs.append("No high-priority items flagged this run.")
    for r in recs:
        P(f"- {r}")

    # ---------- 15. Packet-level Structural Analysis ----------
    H(2, "19. Packet-level Structural Analysis (pktanalysis)")
    P("**What this shows:** the shape of the per-packet structural "
      "features the parser captured - TCP flag combinations, TTL "
      "buckets, and header-anomaly counters.  These features are "
      "orthogonal to payload content: even an encrypted or empty "
      "packet has a flag mask and a TTL.  A flag-combo histogram "
      "exposes scan techniques (NULL/XMAS/SYN+FIN), spec violations "
      "(SYN-with-payload), and spoofing tells (mid-stream payload, "
      "FIN-without-prior-SYN).  TTL bucketing is a coarse OS-family "
      "fingerprint.")
    if pkt_flag_rows:
        H(3, "TCP flag combinations observed")
        P("_Each unique TCP flag bitmap and how often it appears.  "
          "Anomaly column flags combinations that violate the TCP "
          "spec or signal a known scan technique._")
        P("")
        P("| flag_label | mask | packets | share_pct | anomaly |")
        P("| --- | --- | --- | --- | --- |")
        for r in pkt_flag_rows:
            P(f"| {r[0]} | {r[1]} | {r[2]:,} | {r[3]:.3f}% | "
              f"{'YES' if r[4] else ''} |")
    if pkt_anom_rows:
        H(3, "Header anomalies")
        P("_Counts per anomaly class, plus a per-million normalization "
          "so rare events show up usefully against a billion-packet "
          "corpus._")
        P("")
        P("| anomaly | packets | distinct_ips | per_million |")
        P("| --- | --- | --- | --- |")
        for r in pkt_anom_rows:
            P(f"| {r[0]} | {r[1]:,} | {r[2]:,} | {r[3]:.2f} |")
    if pkt_ttl_rows:
        H(3, "TTL buckets (OS family hint)")
        P("_TTL is decremented at each router hop.  Initial-TTL "
          "defaults are: Linux/BSD/macOS=64, Windows=128, "
          "routers/IoT=255.  Bucketing reveals the OS mix of "
          "attackers - very heavy 64-bucket points to Linux-based "
          "scanners; heavy 255-bucket points to router/IoT botnets._")
        P("")
        P("| ttl_bucket | os_family_hint | packets | distinct_ips |")
        P("| --- | --- | --- | --- |")
        for r in pkt_ttl_rows:
            P(f"| {r[0]} | {r[1]} | {r[2]:,} | {r[3]:,} |")

    # ---------- 16. Payload byte-level Analysis ----------
    H(2, "20. Payload Byte-Level Analysis (payloadanalysis)")
    P("**What this shows:** how the bytes of each captured payload "
      "look.  Encoding-class distribution sorts payloads into "
      "ASCII-text / base64-like / hex-like / urlencoded / mixed / "
      "binary buckets - useful for spotting protocols our L7 "
      "parser didn't recognize but that have a tell-tale byte "
      "shape.  Top 4-byte prefixes are *protocol magic* candidates: "
      "many payloads sharing a rare prefix often means a single "
      "tool/exploit/family hiding under `l7_proto=unknown`.")
    if pl_enc_rows:
        H(3, "Payload encoding-class distribution")
        P("_How payloads look at the byte level._")
        P("")
        P(mermaid_pie("Payload encoding class",
                      [(e, b) for e, b, _ in pl_enc_rows]))
        P("")
        P("| encoding | blobs | share_pct |\n| --- | --- | --- |")
        for e, b, sh in pl_enc_rows:
            P(f"| {e} | {b:,} | {sh:.2f}% |")
    if pl_prefix_rows:
        H(3, "Top 25 4-byte payload prefixes")
        P("_The first four bytes of a payload often reveal the protocol "
          "magic.  `47 45 54 20` is `'GET '` (HTTP); `16 03` is TLS "
          "ClientHello; `53 53 48` is `'SSH'`; unusual prefixes can "
          "signal new tools or non-standard protocols._")
        P("")
        P("| prefix_hex | printable | l7 | blobs |")
        P("| --- | --- | --- | --- |")
        for r in pl_prefix_rows:
            P(f"| `{r[0]}` | `{r[1]}` | {r[2]} | {r[3]:,} |")

    # ---------- 17. Pacing & Inter-arrival Timing ----------
    H(2, "21. Pacing & Inter-arrival Timing (pacing)")
    P("**What this shows:** the time intervals between successive "
      "packets from each source IP.  IPs whose IAT has very low "
      "coefficient-of-variation (CV<0.10) are *metronomes* - their "
      "pacing is mechanical, which is a strong fingerprint that "
      "outlasts infrastructure rotation.  A median IAT near 60s or "
      "300s suggests scheduled beaconing; a median near 0 suggests "
      "a burst-then-idle pattern characteristic of mass scanners.")
    if pace_flow_rows:
        H(3, "Connection (TCP flow) duration distribution")
        P("_How long each unique 5-tuple stays alive.  Mostly-sub-second "
          "= single-packet probes; >=1h = persistent connections or "
          "long-running sessions (rare against a honeypot)._")
        P("")
        P(smart_bar("Flow duration distribution",
                              [r[0] for r in pace_flow_rows],
                              [r[1] for r in pace_flow_rows],
                              y_title="flows"))
    if pace_rows:
        H(3, "Top 25 metronome IPs (mechanical pacing)")
        P("_Lowest IAT coefficient-of-variation among top-volume IPs.  "
          "Beacon flags fire when the median inter-arrival matches a "
          "round-number cadence (60s, 300s)._")
        P("")
        P("| src_ip | pkt_count | median_iat_s | cv | beacon_60s | beacon_300s |")
        P("| --- | --- | --- | --- | --- | --- |")
        for r in pace_rows:
            P(f"| {r[0]} | {r[1]:,} | {r[2]:.3f} | {r[3]:.3f} | "
              f"{'YES' if r[4] else ''} | {'YES' if r[5] else ''} |")

    # ---------- 18. Threat Landscape Evolution ----------
    H(2, "22. Threat Landscape Evolution (landscape)")
    P("**What this shows:** how the top targets, tools, and families "
      "shift across the corpus by month.  This is the long-time-"
      "domain view: a static report says *'port 22 was the top "
      "target overall'* but that hides whether 22 was dominant in "
      "all years or specifically during one campaign.  Read the "
      "tables below row-by-row to see when each target/family was "
      "actually active.")
    if landscape_port_rows:
        H(3, "Top destination ports by month (rank<=5)")
        P("_Format: `port:rank` per month.  Rank-1 is the top port "
          "that month.  Sustained appearance of a port at high rank "
          "= persistent target; sudden first-appearance = new campaign._")
        P("")
        by_m: dict[str, list] = {}
        for m, port, ips, rk in landscape_port_rows:
            by_m.setdefault(m, []).append((port, ips, rk))
        P("| month | top_ports (port@rank ips) |")
        P("| --- | --- |")
        for m, items in sorted(by_m.items()):
            compact = " ".join(f"{p}@{rk}({ips})" for p, ips, rk in items)
            P(f"| {m} | {compact} |")
    if landscape_fam_rows:
        H(3, "Botnet family activity by month")
        P("_Per-family distinct-IP counts per month.  Watch for "
          "extinctions and emergence._")
        P("")
        fam_by_m: dict[str, list] = {}
        for m, f, k in landscape_fam_rows:
            fam_by_m.setdefault(m, []).append((f, k))
        P("| month | family:ips ... |")
        P("| --- | --- |")
        for m, items in sorted(fam_by_m.items()):
            compact = " ".join(f"{f}:{k}" for f, k in items)
            P(f"| {m} | {compact} |")

    # ---------- 19. Protocol State-Machine & Cross-Protocol Anomalies ----------
    H(2, "23. Protocol State-Machine & Cross-Protocol Anomalies (protocolanomaly)")
    P("**What this shows:** packets whose place in the TCP state "
      "machine doesn't make sense, traffic on wrong-proto-for-port "
      "combinations, and sources that span multiple L4 transports.  "
      "Mid-stream payload (ACK/PA without a prior SYN from that "
      "src->port pair) is either spoofing or sensor-state-loss.  "
      "SYN with payload is a spec violation usually produced by "
      "raw-socket scanners.  Multi-transport sources are rare "
      "outside of nmap-style tooling and stand out as unusual.")
    if proto_state_rows:
        H(3, "TCP state-machine anomalies")
        P("| anomaly | packets | (src,dst_port) pairs |")
        P("| --- | --- | --- |")
        for r in proto_state_rows:
            P(f"| {r[0]} | {r[1]:,} | {r[2]:,} |")
    if proto_wrong_rows:
        H(3, "Wrong-proto-for-port")
        P("_TCP probes to UDP-typical ports (DNS/SNMP/mDNS/SSDP) and "
          "UDP probes to TCP-typical ports (SSH/HTTP/RDP).  Common "
          "amp/reflection scanning trait._")
        P("")
        P("| proto | dst_port | packets | ips | note |")
        P("| --- | --- | --- | --- | --- |")
        for r in proto_wrong_rows:
            P(f"| {r[0]} | {r[1]} | {r[2]:,} | {r[3]:,} | {r[4]} |")
    if proto_cross_rows:
        H(3, "Top cross-protocol senders (sources using >=2 of TCP/UDP/ICMP)")
        P("_Sources that mix L4 transports with payload-bearing "
          "packets in each.  Rare and worth attention - often "
          "tooling fingerprints._")
        P("")
        P("| src_ip | tcp | udp | icmp | pl_tcp | pl_udp | pl_icmp |")
        P("| --- | --- | --- | --- | --- | --- | --- |")
        for r in proto_cross_rows:
            P(f"| {r[0]} | {'TCP' if r[1] else ''} | "
              f"{'UDP' if r[2] else ''} | {'ICMP' if r[3] else ''} | "
              f"{r[4]:,} | {r[5]:,} | {r[6]:,} |")

    # ---------- 20. SANS ISC Comparison ----------
    H(2, "24. SANS ISC Comparison (isc_compare)")
    P("**What this shows:** how the local sensor's recent activity "
      "compares against the SANS Internet Storm Center global feed.  "
      "Three buckets matter most: (a) ports we see heavily but ISC "
      "doesn't list in its global top - sensor-specific targeting "
      "or fresh campaigns ISC hasn't aggregated yet; (b) ports ISC "
      "sees heavily but we don't - things the sensor isn't catching "
      "because of address/emulation coverage; (c) shared ports - "
      "the validated background of internet scanning that we can "
      "subtract when looking for novelty.")
    if isc_local_only:
        H(3, "Local-only top ports (not in ISC global top)")
        P("| port | local_packets | local_ips |\n| --- | --- | --- |")
        for r in isc_local_only:
            P(f"| {r[0]} | {r[1]:,} | {r[2]:,} |")
    if isc_only_rows:
        H(3, "ISC-only top ports (in ISC global, not in our top-200)")
        P("| port | isc_records | isc_targets |\n| --- | --- | --- |")
        for r in isc_only_rows:
            P(f"| {r[0]} | {r[1]:,} | {r[2]:,} |")
    if isc_shared:
        H(3, "Shared top ports (both)")
        P("| port | isc_records | local_packets | local_ips |")
        P("| --- | --- | --- | --- |")
        for r in isc_shared:
            P(f"| {r[0]} | {r[1]:,} | {r[2]:,} | {r[3]:,} |")

    # ---------- 21. Non-TCP/UDP/ICMP IPv4 traffic ----------
    H(2, "25. Non-TCP/UDP/ICMP IPv4 Traffic (nonipproto)")
    P("**What this shows:** IPv4 traffic on protocols *other than* "
      "TCP/UDP/ICMP that the main parser drops because its protocol "
      "regex only accepts those three.  The honeypi sensor writes "
      "these as `UNKNOWN-IPv4-Protocol:<NUM>` lines - they never reach "
      "the parquet pipeline.  This module rescans the raw sensor log "
      "(the `evolve.py --input` log) to surface them.  Notable categories: "
      "**SCTP (132)** - telco signaling (Diameter, SIGTRAN); "
      "**GRE (47)** - generic tunneling/VPN; "
      "**6to4 (41)** - IPv6 packets wrapped in IPv4; "
      "**IP-in-IP (4)** - encapsulation tunnel; "
      "**ESP/AH (50/51)** - IPsec; "
      "routing protocols (OSPF/EIGRP/PIM) on a public-facing IP "
      "are highly unusual and worth investigating.")
    if nonip_rows:
        H(3, "Compact summary - one row per protocol number")
        P("_Just the volumetric facts.  Description, sample bytes, and "
          "AI decode follow in per-protocol blocks below so the "
          "main table fits the page._")
        P("")
        P("| proto# | name | packets | bytes | srcs | ttl_mode | first | last |")
        P("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in nonip_rows:
            P(f"| {r[0]} | {r[1]} | {r[3]:,} | "
              f"{r[4]:,} | {r[5]:,} | {r[6]} | {r[7]} | {r[8]} |")

        H(3, "Per-protocol detail (sample bytes + AI decode)")
        if aidecode_map:
            model_name = next(iter(aidecode_map.values())).get("model", "claude")
            P(f"_AI decoder: `{model_name}`.  For each protocol we feed "
              "Claude the first 32 IP-payload bytes (after stripping "
              "Ethernet+IPv4 headers) and ask it to identify the format, "
              "decode the leading fields, and assess intent.  All "
              "responses are cached under `output/ai_cache/`._")
        else:
            P("_AI decode not yet run.  Run "
              "`python src/evolve.py aipayloaddecode` to enrich the "
              "blocks below._")
        for r in nonip_rows:
            pn, name, description = r[0], r[1], r[2]
            sample_src, sample_hex, sample_print = r[9], r[10], r[11]
            P("")
            H(4, f"Proto {pn} - {name}")
            P(f"- **IANA description:** {description}")
            P(f"- **Sample sender:** `{sample_src}`")
            P("")
            P("_payload bytes (first 32, after Eth+IPv4 strip):_")
            P("")
            P("```")
            P(f"hex:       {sample_hex}")
            P(f"printable: {sample_print}")
            P("```")
            ai = aidecode_map.get(pn)
            if ai:
                P("")
                P(f"**Claude identifies this as:** {ai['identified_as']} "
                  f"_(confidence: {ai['confidence']})_")
                P("")
                P(f"**Threat assessment:** `{ai['threat_level']}` - "
                  f"{ai['threat_summary']}")
                P("")
                try:
                    fields = json.loads(ai["decoded_fields"])
                except Exception:
                    fields = {}
                if fields:
                    P("_decoded fields:_")
                    P("")
                    P("| field | value |\n| --- | --- |")
                    for k, v in fields.items():
                        v_str = str(v).replace("|", "\\|")[:200]
                        P(f"| {k} | {v_str} |")
                    P("")
                P(f"_analysis:_ {ai['analysis']}")
    else:
        P("")
        P("> _No nonipproto output yet.  Run `python src/evolve.py "
          "nonipproto` to populate this section._")

    # ---------- 26. Per-IP packet choreography fingerprints (chainfp) ----------
    # Explicit HTML anchor so the chainfp cross-signal findings' report_anchor
    # (#chain-fingerprints-chainfp) resolves regardless of heading slugification.
    md.append('\n<a id="chain-fingerprints-chainfp"></a>')
    H(2, "26. Per-IP Packet Choreography Fingerprints (chainfp)")
    P("**What this shows:** the *temporal order* in which a source's packets "
      "arrive within one session, encoded as a chain of "
      "`<flag_mask>-<proto>/<port>` tokens (Ron Dilley's `sensorChain.pl` "
      "grammar, ListonCon 2023).  Where every other analyzer aggregates a "
      "source into counts and sets - erasing order - chains preserve it, so "
      "`SYN-then-own-RST`, `RST-without-prior-SYN`, and no-teardown sequences "
      "become visible.  The tool sweeps several session windows and keeps the "
      "one whose chain-frequency distribution has the highest Shannon entropy "
      "(best signal-to-noise); the `distinctive` tier (10-99 sources sharing a "
      "chain) is the toolkit-fingerprint sweet spot.")
    if chainfp_best:
        P("")
        P(f"- **Best-SNR window:** `{chainfp_best['label']}` "
          f"({chainfp_best['entropy_bits']:.2f} bits over "
          f"{chainfp_best['distinct_chains']:,} distinct chains)")
        if chainfp_timed_path.exists():
            P("- A **timed** variant (`chainfp_timed.parquet`) annotates each "
              "token with its per-source-normalized inter-arrival cadence, "
              "splitting look-alike sequences that move on different clocks.")
    if chainfp_snr_rows:
        H(3, "Window signal-to-noise comparison")
        P("_Higher entropy = the window separates distinct behaviours better.  "
          "The flagged window is used for the findings above._")
        P("")
        P("| window | seconds | distinct_chains | total_obs | entropy_bits | best |")
        P("| --- | --- | --- | --- | --- | --- |")
        for wl, ws, dc, obs, ent, is_best in chainfp_snr_rows:
            P(f"| {wl} | {ws:,} | {dc:,} | {obs:,} | {ent:.2f} "
              f"| {'**YES**' if is_best else ''} |")
    if chainfp_distinctive:
        H(3, "Top distinctive / rare chains (best-SNR window)")
        P("_Cohesive small-cluster choreographies - rare enough to be a "
          "toolkit signature, not internet-background noise.  ICMP-echo-only "
          "ping floods are excluded._")
        P("")
        P("| sources | packets | tokens | tier | dst_ports | chain |")
        P("| --- | --- | --- | --- | --- | --- |")
        for chain, sc, pk, tok, ports, tier in chainfp_distinctive:
            chain_disp = (chain or "")[:64].replace("|", "\\|")
            ports_disp = (ports or "")[:24].replace("|", "\\|")
            P(f"| {sc:,} | {int(pk or 0):,} | {tok} | {tier} | {ports_disp} "
              f"| `{chain_disp}` |")
    if not (chainfp_best or chainfp_distinctive):
        P("")
        P("> _No chainfp output yet.  Run `python src/evolve.py chainfp` to "
          "populate this section._")

    # ---------- 27. Behavioral fingerprint rotation (compositeprint) ----------
    # Explicit HTML anchor so the cross-signal findings' report_anchor
    # (#composite-fingerprints-compositeprint) resolves regardless of how a
    # given markdown renderer slugifies the numbered heading.
    md.append('\n<a id="composite-fingerprints-compositeprint"></a>')
    H(2, "27. Behavioral Fingerprint Rotation (compositeprint)")
    P("**What this shows:** every source's behaviour in an *adaptive activity "
      "episode* is fused into one `core_hash` over five dimensions - the TCP/IP "
      "stack (TTL/window/proto-mix), the proto/port **sequence** (chainfp "
      "choreography), the inter-packet **timing** (per-source-normalized "
      "cadence), the **app** client (JA4/JA4H/JA4SSH), and the **payload**.  "
      "The hash deliberately excludes ASN/CIDR/IP, so the *same* `core_hash` "
      "seen from many networks is **one tool/campaign that rotated its "
      "infrastructure** - the behaviour-survives-hosting signal that per-IP "
      "analyzers cannot see.  A cluster spanning >= 2 ASNs or CIDRs is flagged "
      "`cross_infra`.")
    if composite_summary.get("episodes"):
        P("")
        P(f"- **{composite_summary['episodes']:,}** episodes across "
          f"**{composite_summary['ips']:,}** source IPs")
        P(f"- **{composite_summary['cores']:,}** distinct behavioral "
          f"fingerprints (core_hash)")
        if "clusters" in composite_summary:
            P(f"- **{composite_summary['clusters']:,}** fingerprints shared by "
              f">= 2 IPs; **{composite_summary['cross_infra']:,}** of those span "
              f"multiple ASNs/CIDRs (widest: "
              f"{composite_summary.get('max_asns', 0)} ASNs)")
    if composite_cross_rows:
        H(3, "Top cross-infrastructure behavioral fingerprints")
        P("_Each row is one fused fingerprint deployed across multiple networks.  "
          "`present` = a(pp)/p(ayload) channels carried; bare scans show `--`.  "
          "Generic ICMP ping sweeps are excluded._")
        P("")
        P("| core_hash | tier | IPs | ASNs | CIDRs | countries | pkts | span_h | present | dst_port | sequence |")
        P("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for (core_hash, tier, n_ips, n_asns, n_cidrs, n_ctry, pkts, span_h,
             present, dom_proto, rep_port, seq, sample_asns) in composite_cross_rows:
            seq_disp = (seq or "")[:54].replace("|", "\\|")
            P(f"| `{core_hash[:12]}` | {tier} | {n_ips} | {n_asns} | {n_cidrs} "
              f"| {n_ctry} | {int(pkts or 0):,} | {span_h:.1f} | {present} "
              f"| {rep_port} | {seq_disp} |")
        P("")
        P("_The cross-signal findings above (section 0.5, "
          "`infrastructure-rotation`) promote the widest-spread and "
          "re-emergent fingerprints to ranked findings with severity._")
    elif comp_ep_path.exists():
        P("")
        P("_No multi-IP behavioral clusters this run (every fingerprint was "
          "unique to one source)._")
    else:
        P("")
        P("> _No compositeprint output yet.  Run `python src/evolve.py "
          "compositeprint` to populate this section._")

    # ---------- 28. Campaign migration across infrastructure ----------
    md.append('\n<a id="campaign-migration-campaignmigration"></a>')
    H(2, "28. Campaign Migration Across Infrastructure (campaignmigration)")
    P("**What this shows:** how each campaign fingerprint (a compositeprint "
      "`core_hash`) **rotates across ASNs/CIDRs/IPs over time** to dodge "
      "blocklists.  Two intelligence products fall out of the migration "
      "pattern: an **ISP-collaboration graph** (networks linked by hosting the "
      "*same* fingerprints -- the complicit / bulletproof / persistently-"
      "compromised cluster) and **compromised-host churn** (source IPs reused "
      "across campaigns or kept alive for days -- candidate cycled relays).  "
      "Per-campaign migration timelines (Gantt) are in "
      "`reports/campaignmigration/migration.md`.")
    if migration_summary.get("campaigns"):
        P("")
        P(f"- **{migration_summary['campaigns']:,}** migrating campaigns across "
          f"**{migration_summary['asns']:,}** ASNs")
        P(f"- compromised hosts: **{migration_summary.get('host_cycled', 0):,}** "
          f"cycled (reused across >= 2 campaigns), "
          f"**{migration_summary.get('host_persistent', 0):,}** persistent "
          f"relays, **{migration_summary.get('host_transient', 0):,}** transient")
    if migration_cohost:
        H(3, "ISP collaboration - ASNs hosting the same campaigns")
        P("_Edge weight = number of distinct campaign fingerprints shared._")
        P("")
        nodes = {}
        edges = []
        for sa, so, da, do, n in migration_cohost:
            nodes[f"AS{sa}"] = f"AS{sa} {mm_trunc(so or '', 22)}".strip()
            nodes[f"AS{da}"] = f"AS{da} {mm_trunc(do or '', 22)}".strip()
            edges.append((f"AS{sa}", f"AS{da}", str(n)))
        P(mermaid_flowchart("LR", list(nodes.items()), edges))
        P("")
    if migration_handoff:
        H(3, "Migration hand-offs (campaign moved AS-A -> AS-B)")
        P("")
        P(mermaid_sankey([(f"AS{sa} {mm_trunc(so or '', 18)}".strip(),
                           f"AS{da} {mm_trunc(do or '', 18)}".strip(), n)
                          for sa, so, da, do, n in migration_handoff]))
        P("")
    if migration_hosts:
        H(3, "Top cycled / persistent source hosts")
        P("_Candidate compromised relays reused across campaigns or kept "
          "alive across days._")
        P("")
        P("| src_ip | class | campaigns | active_days | packets | asn | country |")
        P("| --- | --- | --- | --- | --- | --- | --- |")
        for ip, cls, ncamp, adays, pkts, asn, ciso in migration_hosts:
            P(f"| {ip} | {cls} | {ncamp} | {adays} | {int(pkts or 0):,} "
              f"| AS{asn} | {ciso or ''} |")
    if not migration_summary.get("campaigns"):
        P("")
        P("> _No campaignmigration output yet.  Run `python src/evolve.py "
          "campaignmigration` to populate this section._")

    # ---------- 29. MITRE ATT&CK coverage ----------
    H(2, "29. MITRE ATT&CK Technique Coverage (attackmap)")
    P("**What this shows:** observed honeypot behaviors mapped to MITRE "
      "ATT&CK technique IDs (rule-based, derived from portscans, rdpbrute, "
      "probesigs, droppers, botnetcls, and tlsintel).  `evidence_count` is "
      "the number of supporting analyzer rows -- a relative volume signal, "
      "not a severity ranking.")
    _con_atk = lib.duck()
    atk_rows = safe_read_table(_con_atk,
                               lib.REPORTS / "attackmap" / "attackmap.parquet")
    _con_atk.close()
    if atk_rows:
        atk_rows = sorted(atk_rows, key=lambda r: (r[1] or 0), reverse=True)
        P("")
        P(f"**{len(atk_rows)}** distinct techniques observed.")
        P("")
        P("| technique | evidence_count | sources |")
        P("| --- | --- | --- |")
        for tech, cnt, sources in atk_rows:
            P(f"| {tech} | {int(cnt or 0):,} | {sources or ''} |")
    else:
        P("")
        P("> _No attackmap output yet.  It runs under the `analyzers` stage; "
          "run `python src/evolve.py analyzers` to populate this section._")

    # ---------- 30. HTTP request templates ----------
    H(2, "30. HTTP Request Templates (httppatterns)")
    P("**What this shows:** **intent-bearing** HTTP attack requests (exploit "
      "URIs, non-GET methods, queries, traversal) clustered by structural "
      "similarity into reusable templates.  The bare `GET /` root probe (~75% "
      "of HTTP on this ultra-low-interaction sensor) is excluded — its only "
      "signal is the client header set, already covered by JA4H.  `novel` marks "
      "templates with no `probesigs` signature (the marginal discovery over "
      "hand-written rules).")
    hp_summary = lib.REPORTS / "http_patterns" / "summary.json"
    if hp_summary.exists():
        import json as _json
        s = _json.loads(hp_summary.read_text())
        cov = s.get("coverage_estimate")
        P("")
        P(f"- **{s.get('distinct_payloads', 0):,}** distinct intent-bearing HTTP "
          f"payloads → **{s.get('clusters', 0):,}** templates "
          f"(**{s.get('novel_clusters', 0):,}** novel vs probesigs)")
        if cov is not None:
            P(f"- coverage estimate: **{cov*100:.1f}%** of intent-bearing "
              f"requests fall into a recurring template (rest are one-off)")
    _con_hp = lib.duck()
    hp_rows = safe_read_table(_con_hp,
                              lib.REPORTS / "http_patterns" / "http_patterns.parquet")
    _con_hp.close()
    if hp_rows:
        hp_rows = sorted(hp_rows, key=lambda r: (r[3] or 0), reverse=True)[:25]
        P("")
        P("| template | distinct | volume | novel |")
        P("| --- | --- | --- | --- |")
        for cid, tmpl, distinct, vol, share, novel, sample in hp_rows:
            safe = str(tmpl).replace("|", "\\|")[:90]
            P(f"| `{safe}` | {int(distinct or 0):,} | {int(vol or 0):,} "
              f"| {'yes' if novel else ''} |")
    else:
        P("")
        P("> _No httppatterns output yet.  Run `python src/evolve.py "
          "httppatterns` to populate this section._")

    # ---------- Threat storylines (KG-lite finding fusion) ----------
    H(2, "31. Threat Storylines (KG-lite finding fusion)")
    P("**What this shows:** the cross-signal findings (sections above) fused "
      "into operator-level **storylines**.  `conclusions/graph.py` links any two "
      "findings that share a strong entity — a compositeprint `core_hash` "
      "(infrastructure-independent fingerprint), a packet-choreography chain, the "
      "same payload on the same port, or source IPs — or two weak ones (a port "
      "and an activity day, two ASNs) — then groups the connected findings.  "
      "Payload, port, day and l7 protocol come from the members' own packets, so "
      "findings of different analyzers (neuromorphic flag groups, l7 surges, "
      "miner rules, landscape ports, burst chains) can meet.  Shared IPs count "
      "only when they are a real part of both findings, and known and behavioral "
      "scanners (scannerintel `benign_org`, the benignfilter scanner ASNs, "
      "portscans) are left out of IP links; they keep their flags and risk.  A "
      "storyline reads as one campaign instead of N disconnected cards.")
    _story_summary = lib.OUTPUT_DIR / "conclusions" / "storylines" / "summary.json"
    if _story_summary.exists():
        import json as _json
        ss = _json.loads(_story_summary.read_text())
        ratio = ss.get("finding_consolidation_ratio")
        P("")
        P(f"- **{ss.get('n_findings', 0):,}** findings → "
          f"**{ss.get('n_storylines', 0):,}** storylines "
          f"(**{ss.get('n_multi_finding', 0):,}** multi-finding); "
          f"largest groups **{ss.get('largest_storyline_findings', 0)}** findings")
        if ratio is not None:
            P(f"- consolidation ratio **{ratio:.2f}** "
              f"(1.0 = nothing fused; lower = more campaigns collapsed)")
    # Storylines with 2+ findings, with the verdict mix of their findings
    # (the correlator severity says nothing about a benign BitTorrent swarm).
    _stories = lib.OUTPUT_DIR / "conclusions" / "storylines" / "storylines.parquet"
    story_rows: list[dict] = []
    if _stories.exists():
        try:
            story_rows = [r for r in pq.read_table(_stories, columns=[
                "storyline_id", "finding_count", "finding_ids", "pattern_ids",
                "src_ip_count", "linking_entities", "first_seen", "last_seen",
            ]).to_pylist() if r["finding_count"] >= 2]
        except Exception as e:
            print(f"[report] could not read storylines: {e}", file=sys.stderr)
    if story_rows:
        vmap = {r["finding_id"]: r["verdict"] for r in verdict_rows}
        story_rows.sort(key=lambda r: (-r["finding_count"], r["storyline_id"]))
        P("")
        P("| storyline | findings | verdicts | sources | linked by | seen |")
        P("| --- | ---: | --- | ---: | --- | --- |")
        for sr in story_rows:
            mix = Counter(vmap.get(f, "?") for f in json.loads(sr["finding_ids"]))
            mix_s = ", ".join(f"{v} {n}" for v, n in mix.most_common())
            links = ", ".join(f"{k} {v}" for k, v in
                              json.loads(sr["linking_entities"] or "{}").items())
            P(f"| `{sr['storyline_id']}` | {sr['finding_count']} | {mix_s} | "
              f"{sr['src_ip_count']:,} | {links} | "
              f"{(sr['first_seen'] or '')[:10]} to {(sr['last_seen'] or '')[:10]} |")
    else:
        P("")
        P("> _No multi-finding storylines yet.  Run `python src/evolve.py kg` "
          "to populate this section._")

    # ---------- 32. Neuromorphic per-source scores (neuro) ----------
    H(2, "32. Neuromorphic Per-Source Scores (neuro: LIF, arrival, HDC)")
    P("**What this shows:** the per-source detectors of the neuromorphic "
      "plan (ARCHITECTURE §9).  The **LIF / ALIF bank** reads each source's "
      "packet rate per day: `change` is the largest sustained shift of its "
      "own rate, `reg` is how mechanical (metronome-like) its timing is.  "
      "**HDC** encodes each session's packet choreography as a binary "
      "hypervector: `hdc_proto` scores a choreography no known cluster "
      "explains, `hdc_drift` a source whose choreography changes.  Every "
      "readout is calibrated against the previous days (-log10 exceedance "
      "among comparable source-days); a source-day is **flagged** at >= 4.  "
      "The **arrival** detector marks minutes with an abnormal flood of new "
      "sources.  The flags add a capped `neuro_signal` term to the risk "
      "score (LIF <= 6, HDC <= 4, total <= 8; arrival is 0 by operator "
      "decision).")
    neuro_path = lib.OUTPUT_DIR / "reports" / "neuro" / "neuro.parquet"
    if neuro_path.exists():
        ncon = lib.duck()
        n = ncon.execute(f"""
            SELECT count(*) FILTER (WHERE lif_days > 0),
                   coalesce(sum(lif_days), 0),
                   count(*) FILTER (WHERE lif_flag_days > 0),
                   count(*) FILTER (WHERE hdc_days > 0),
                   coalesce(sum(hdc_days), 0),
                   count(*) FILTER (WHERE hdc_flag_days > 0),
                   count(*) FILTER (WHERE arrival_alarm_minutes > 0),
                   count(*) FILTER (WHERE arrival_first_in_alarm)
            FROM read_parquet('{neuro_path}')""").fetchone()
        P("")
        P("| detector | sources scored | source-days | sources flagged (>= 4) |")
        P("| --- | ---: | ---: | ---: |")
        P(f"| LIF / ALIF (change, reg) | {n[0]:,} | {n[1]:,} | {n[2]:,} |")
        P(f"| HDC (proto, drift) | {n[3]:,} | {n[4]:,} | {n[5]:,} |")
        P(f"| arrival alarms | {n[6]:,} in an alarm minute | -- | "
          f"{n[7]:,} first seen in one |")
        if risk_path.exists():
            nr = ncon.execute(f"""
                SELECT risk_tier, count(*),
                       count(*) FILTER (WHERE rationale LIKE '%lif-%'),
                       count(*) FILTER (WHERE rationale LIKE '%hdc-%')
                FROM read_parquet('{risk_path}') WHERE neuro_signal > 0
                GROUP BY 1""").fetchall()
            if nr:
                order = {t: i for i, t in enumerate(
                    ("critical", "high", "medium", "low", "info"))}
                nr.sort(key=lambda r: order.get(r[0], 9))
                H(3, "Sources with a neuro risk term, by tier")
                P("| tier | sources | LIF term | HDC term |")
                P("| --- | ---: | ---: | ---: |")
                for tier, cnt, lif_n, hdc_n in nr:
                    P(f"| {tier} | {cnt:,} | {lif_n:,} | {hdc_n:,} |")
            top = ncon.execute(f"""
                SELECT r.src_ip, r.risk_tier, r.risk_score, r.neuro_signal,
                       n.lif_max, n.lif_flag_days, n.lif_best_day,
                       greatest(n.hdc_proto_max, n.hdc_drift_max),
                       n.hdc_flag_days, n.hdc_best_day
                FROM read_parquet('{risk_path}') r
                JOIN read_parquet('{neuro_path}') n USING (src_ip)
                WHERE r.neuro_signal > 0
                ORDER BY r.neuro_signal DESC, r.risk_score DESC LIMIT 25
            """).fetchall()
            if top:
                H(3, "Top 25 sources by neuro risk term")
                P("| src_ip | tier | risk | neuro | lif_max | lif flag days "
                  "| lif best day | hdc_max | hdc flag days | hdc best day |")
                P("| --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | --- |")
                f = lambda v: "--" if v is None else f"{v:.2f}"
                for (ip, tier, rs, ns, lm, lfd, lbd, hm, hfd, hbd) in top:
                    P(f"| {ip} | {tier} | {rs:.1f} | {ns:.2f} | {f(lm)} "
                      f"| {lfd or 0} | {lbd or '--'} | {f(hm)} | {hfd or 0} "
                      f"| {hbd or '--'} |")
        hdc_top = ncon.execute(f"""
            SELECT hdc_best_day, count(*) AS n,
                   string_agg(src_ip, ', ' ORDER BY src_ip)
            FROM read_parquet('{neuro_path}') WHERE hdc_flag_days > 0
            GROUP BY 1 ORDER BY n DESC, 1 LIMIT 10""").fetchall()
        if hdc_top:
            H(3, "HDC-flagged sources grouped by their best day")
            P("_HDC flags arrive in groups: related sources that share one "
              "unexplained choreography on the same day._")
            P("")
            P("| day | sources | src_ips |")
            P("| --- | ---: | --- |")
            for day, cnt, ips in hdc_top:
                ips_disp = ips if len(ips) <= 160 else ips[:157] + "..."
                P(f"| {day} | {cnt} | {ips_disp} |")
        ncon.close()
    else:
        P("")
        P("> _No neuro output yet.  Run `python src/evolve.py neuro` to "
          "populate this section._")

    # ---------- Appendix ----------
    H(2, "Appendix A. Per-analyzer data coverage")
    analyzer_dirs = sorted((p.name for p in lib.REPORTS.iterdir() if p.is_dir()))
    P("| analyzer | output_size_bytes | rows |\n| --- | --- | --- |")
    con = lib.duck()
    for name in analyzer_dirs:
        p = lib.REPORTS / name / f"{name}.parquet"
        if p.exists() and p.stat().st_size > 0:
            try:
                rows = con.execute(f"SELECT count(*) FROM read_parquet('{p}')").fetchone()[0]
            except Exception:
                rows = "?"
            P(f"| {name} | {p.stat().st_size:,} | {rows} |")
        else:
            P(f"| {name} | -- | -- |")
    con.close()

    H(2, "Appendix B. Glossary")
    P("""
- **Risk tier**: composite score band - critical >=80, high 60-80, medium 40-60, low 20-40, info <20.
- **Attack stage**: R/P/X/C/D/B as defined in section 5.
- **Auto-promoted rule**: itemset with >=85% threat-purity over >=50 IPs and only behavioral tokens (port/asn/cc/l7).
- **Drift**: two-sample Kolmogorov-Smirnov test on a feature distribution between recent 7d and baseline 60d.
- **Cluster**: HDBSCAN result over normalized per-IP feature vectors.
- **Coordination wave**: a single payload SHA-256 sent by N+ distinct IPs ranked by tightness (IPs/min).
- **Sensor outage**: a run of whole UTC days with no packets (no `packets` day partition); listed in section 1.
""")

    P("\n---\n_End of report._\n")

    md_text = "\n".join(md)
    OUT_PATH.write_text(md_text)
    print(f"[report] wrote {OUT_PATH} ({len(md):,} lines)", file=sys.stderr)

    if not args.no_html:
        try:
            write_html(md_text, HTML_PATH)
            print(f"[report] wrote {HTML_PATH}", file=sys.stderr)
        except Exception as e:
            print(f"[report] HTML render failed: {e}", file=sys.stderr)

    if not args.no_pdf:
        try:
            write_pdf(md_text, PDF_PATH)
            print(f"[report] wrote {PDF_PATH}", file=sys.stderr)
        except Exception as e:
            print(f"[report] PDF render failed: {e}", file=sys.stderr)

    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-html", action="store_true", help="Skip HTML render")
    ap.add_argument("--no-pdf",  action="store_true", help="Skip PDF render")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

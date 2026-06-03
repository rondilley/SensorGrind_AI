#!/usr/bin/env python3
"""
asnintel - per-ASN threat profile for defender attribution.

Goal: answer "which networks are predominantly hostile to me, and what
do they specialize in?"  Per-ASN aggregations of risk, targeting,
tooling, and persistence so defenders can make ASN-level block
decisions intelligently.

Outputs per-ASN:
  - threat_density     fraction of ASN's IPs at medium+ risk tier
  - dominant_targets   top 5 dst_ports the ASN's IPs hit
  - dominant_tooling   top toolkit fingerprints among the ASN's IPs
                       (UA hash, JA4T, common URI tags)
  - persistence_p50    median lifetime (days) of the ASN's threat IPs
  - bulletproof_flag   heuristic flag for known-bulletproof hosters
  - cooperation_score  internal-correlation score: how synchronized are
                       activity windows across IPs from this ASN?
  - block_recommended  defender-actionable risk grade
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import features as sf
from sg import lib

FEATURE_VERSION = 1
OUT_DIR = lib.REPORTS / "asnintel"

BULLETPROOF_KEYWORDS = (
    "media land", "skynet network", "tamatiya", "iptransit business",
    "mevspace", "layer7 networks", "iproyal", "net-surf",
    "ip volume", "pfcloud", "latitude.sh", "selectel", "salyam",
    "ds1.host", "redbytes", "stealth", "fortress", "diel",
    "private layer", "njalla", "ferdinand", "tessosec",
)

RESULT_SCHEMA = pa.schema([
    ("asn",              pa.uint32()),
    ("asn_org",          pa.string()),
    ("country_iso",      pa.string()),
    ("ip_count",         pa.uint32()),
    ("threat_ip_count",  pa.uint32()),
    ("threat_density",   pa.float32()),
    ("pkt_total",        pa.uint64()),
    ("threat_pkt_share", pa.float32()),
    ("top_ports",        pa.string()),
    ("top_botnet_fams",  pa.string()),
    ("top_probe_tags",   pa.string()),
    ("median_days",      pa.float32()),
    ("p90_days",         pa.float32()),
    ("bulletproof_flag", pa.bool_()),
    ("cooperation_score", pa.float32()),
    ("risk_grade",       pa.string()),
    ("block_recommend",  pa.string()),
])


def _grade(density: float, n: int, bulletproof: bool, coop: float) -> tuple[str, str]:
    """Map (threat_density, ip_count, bulletproof_flag, cooperation_score)
    to a defender-actionable grade + recommendation string."""
    if n < 5:
        return "info", "too few IPs for ASN-level action"
    if density >= 0.95 and n >= 20:
        return "block_asn", f"{density:.0%} of {n:,} IPs are threats; bulk-block ASN"
    if density >= 0.80 and bulletproof:
        return "block_asn", "bulletproof hoster with high threat density - block ASN"
    if density >= 0.80:
        return "monitor_block", "very high threat density - prefer ASN-block, fallback per-IP block"
    if density >= 0.50:
        return "watch", "majority hostile - watch for new IPs in this ASN"
    if density >= 0.20 and coop >= 0.5:
        return "investigate", "moderate density + synchronized internal activity - looks like a campaign"
    if density >= 0.20:
        return "per-ip", "blocklist worst IPs; ASN-block is too coarse"
    return "info", "low threat density - per-IP risk-based action only"


def run(args: argparse.Namespace) -> int:
    snap = sf.latest_snapshot("ip", FEATURE_VERSION)
    if snap is None:
        print("[asnintel] no ip features", file=sys.stderr)
        return 2
    feat_path = sf.snapshot_dir(snap) / "part-0000.parquet"
    risk_path = (lib.OUTPUT_DIR / "risk" / "ip_risk"
                 / f"dt={snap.snapshot_date.isoformat()}" / "risk.parquet")
    if not risk_path.exists():
        print("[asnintel] no risk file; run risk stage first", file=sys.stderr)
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    con = lib.duck(memory_limit="16GB")
    lib.register_views(con, clustered=True)

    probesigs_path = lib.REPORTS / "probesigs" / "probesigs.parquet"
    botnet_path = lib.REPORTS / "botnetcls" / "botnetcls.parquet"

    print("[asnintel] aggregating per-ASN threat profile...", file=sys.stderr)
    rows = con.execute(f"""
        WITH ip AS (
            SELECT f.src_ip, f.asn, f.asn_org, f.country_iso,
                   f.pkt_count, f.day_count,
                   r.risk_score, r.risk_tier
            FROM read_parquet('{feat_path}') f
            JOIN read_parquet('{risk_path}') r ON f.src_ip = r.src_ip
            WHERE f.asn IS NOT NULL AND f.asn > 0
        )
        SELECT asn,
               min(asn_org)                                               AS asn_org,
               min(country_iso)                                           AS country_iso,
               count(*)                                                   AS ip_count,
               count(*) FILTER (WHERE risk_tier IN ('critical','high','medium')) AS threat_ip_count,
               sum(pkt_count)                                             AS pkt_total,
               sum(pkt_count) FILTER (WHERE risk_tier IN ('critical','high','medium'))
                                                                          AS threat_pkts,
               median(day_count) FILTER (WHERE risk_tier IN ('critical','high','medium'))
                                                                          AS median_days,
               quantile_cont(day_count, 0.9) FILTER (WHERE risk_tier IN ('critical','high','medium'))
                                                                          AS p90_days
        FROM ip
        GROUP BY asn
        HAVING count(*) >= 5
        ORDER BY count(*) FILTER (WHERE risk_tier IN ('critical','high','medium')) DESC
    """).fetchall()
    print(f"[asnintel] {len(rows):,} ASNs with 5+ observed IPs", file=sys.stderr)

    # Materialize (src_ip, asn) for the candidate ASN set ONCE so the four
    # downstream queries below (top ports, top botnet families, top probe
    # tags, cooperation score) each issue a single packets-JOIN against a
    # small in-memory table instead of joining packets to the full
    # 1.1B-row feature parquet four separate times.
    print("[asnintel] materializing candidate (src_ip, asn) map...",
          file=sys.stderr)
    asn_set = ", ".join(str(int(r[0])) for r in rows)
    con.execute(f"""
        CREATE TEMP TABLE asn_ip AS
        SELECT src_ip, asn
        FROM read_parquet('{feat_path}')
        WHERE asn IN ({asn_set})
    """)
    asn_ip_n = con.execute("SELECT count(*) FROM asn_ip").fetchone()[0]
    print(f"[asnintel]   {asn_ip_n:,} (src_ip, asn) tuples", file=sys.stderr)

    print("[asnintel] gathering per-ASN dominant ports/families/probes...",
          file=sys.stderr)
    # Top ports per ASN
    port_rows = con.execute("""
        WITH ranked AS (
            SELECT a.asn, p.dst_port, count(*) AS n,
                   row_number() OVER (PARTITION BY a.asn ORDER BY count(*) DESC, p.dst_port ASC) AS rk
            FROM packets p
            JOIN asn_ip a ON p.src_ip = a.src_ip
            WHERE p.dst_port IS NOT NULL
            GROUP BY a.asn, p.dst_port
        )
        SELECT asn, dst_port, n FROM ranked WHERE rk <= 5
    """).fetchall()
    asn_ports: dict[int, list] = {}
    for asn, port, n in port_rows:
        asn_ports.setdefault(int(asn), []).append(f"{port}({n:,})")

    asn_fams: dict[int, list] = {}
    if botnet_path.exists():
        fam_rows = con.execute(f"""
            WITH ranked AS (
                SELECT a.asn, b.family, count(DISTINCT p.src_ip) AS ips,
                       row_number() OVER (PARTITION BY a.asn ORDER BY count(DISTINCT p.src_ip) DESC, b.family ASC) AS rk
                FROM packets p
                JOIN asn_ip a ON p.src_ip = a.src_ip
                JOIN read_parquet('{botnet_path}') b ON p.payload_sha256 = b.payload_sha256
                GROUP BY a.asn, b.family
            )
            SELECT asn, family, ips FROM ranked WHERE rk <= 3
        """).fetchall()
        for asn, fam, n in fam_rows:
            asn_fams.setdefault(int(asn), []).append(f"{fam}({n:,})")

    asn_probes: dict[int, list] = {}
    if probesigs_path.exists():
        prb_rows = con.execute(f"""
            WITH ranked AS (
                SELECT a.asn, p.probe_tag, count(DISTINCT i.src_ip) AS ips,
                       row_number() OVER (PARTITION BY a.asn ORDER BY count(DISTINCT i.src_ip) DESC, p.probe_tag ASC) AS rk
                FROM iocs i
                JOIN asn_ip a ON i.src_ip = a.src_ip
                JOIN read_parquet('{probesigs_path}') p ON i.value = p.uri
                WHERE i.ioc_kind = {lib.IOC_ID['http_uri']}
                GROUP BY a.asn, p.probe_tag
            )
            SELECT asn, probe_tag, ips FROM ranked WHERE rk <= 3
        """).fetchall()
        for asn, tag, n in prb_rows:
            asn_probes.setdefault(int(asn), []).append(f"{tag}({n:,})")

    # Cooperation score: fraction of an ASN's IPs whose activity hours overlap
    # significantly.  Approximated by: per ASN, count distinct dt-hour buckets
    # where >=2 IPs were active simultaneously, divided by total active buckets.
    print("[asnintel] computing cooperation (synchronized activity) score...",
          file=sys.stderr)
    coop_rows = con.execute("""
        WITH a AS (
            SELECT ai.asn, p.src_ip,
                   date_trunc('hour', p.ts) AS hr
            FROM packets p
            JOIN asn_ip ai ON p.src_ip = ai.src_ip
            GROUP BY ai.asn, p.src_ip, hr
        ),
        bucket_pop AS (
            SELECT asn, hr, count(*) AS n_ips_active
            FROM a GROUP BY asn, hr
        )
        SELECT asn,
               sum(CASE WHEN n_ips_active >= 2 THEN 1 ELSE 0 END) * 1.0
               / nullif(count(*), 0) AS coop
        FROM bucket_pop GROUP BY asn
    """).fetchall()
    coop_map = {int(r[0]): float(r[1] or 0) for r in coop_rows}

    con.close()

    out_rows: list[dict] = []
    for r in rows:
        asn, asn_org, cc, n, threat_n, pkt_total, threat_pkts, med, p90 = r
        density = (threat_n / n) if n else 0.0
        org_lower = (asn_org or "").lower()
        bullet = any(k in org_lower for k in BULLETPROOF_KEYWORDS)
        coop = coop_map.get(int(asn), 0.0)
        grade, rec = _grade(density, int(n), bullet, coop)
        out_rows.append({
            "asn": int(asn), "asn_org": asn_org or "",
            "country_iso": cc or "",
            "ip_count": int(n), "threat_ip_count": int(threat_n),
            "threat_density": float(density),
            "pkt_total": int(pkt_total or 0),
            "threat_pkt_share": float((threat_pkts or 0) / pkt_total) if pkt_total else 0.0,
            "top_ports": ", ".join(asn_ports.get(int(asn), [])),
            "top_botnet_fams": ", ".join(asn_fams.get(int(asn), [])),
            "top_probe_tags": ", ".join(asn_probes.get(int(asn), [])),
            "median_days": float(med or 0),
            "p90_days":    float(p90 or 0),
            "bulletproof_flag": bool(bullet),
            "cooperation_score": float(coop),
            "risk_grade": grade,
            "block_recommend": rec,
        })

    out_rows.sort(key=lambda r: (-r["threat_ip_count"], -r["threat_density"]))
    pq.write_table(pa.Table.from_pylist(out_rows, schema=RESULT_SCHEMA),
                   OUT_DIR / "asnintel.parquet",
                   compression="zstd", compression_level=3)

    md = [
        "# asnintel - per-ASN threat profile + defender recommendation", "",
        f"_Profiled {len(out_rows):,} ASNs (>=5 observed IPs each)._  ",
        "_`threat_density` = fraction of an ASN's IPs that are at medium+ "
        "risk tier; `cooperation_score` = fraction of hour-buckets where "
        ">=2 IPs from the ASN were simultaneously active (a proxy for "
        "central command/coordination); `bulletproof_flag` = the ASN's "
        "org name matches a known hostile-hosting keyword._",
        "",
        "## Grade scale",
        "",
        "| grade | meaning |",
        "| --- | --- |",
        "| `block_asn` | Bulk-block the entire ASN safely |",
        "| `monitor_block` | Block now, monitor for false-positive collateral |",
        "| `watch` | Treat traffic from this ASN with heightened scrutiny |",
        "| `investigate` | Coordinated internal activity suggests a campaign |",
        "| `per-ip` | ASN is too mixed; act per-IP only |",
        "| `info` | Low risk - no ASN-level action recommended |",
        "",
        "## Top 50 ASNs by threat-IP count",
        "",
        "| asn | org | cc | ips | threat_ips | density | coop | bp | top_ports | top_fams | top_probes | grade | recommendation |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in out_rows[:50]:
        md.append(
            f"| {r['asn']} | {r['asn_org'][:32]} | {r['country_iso']} | "
            f"{r['ip_count']:,} | {r['threat_ip_count']:,} | "
            f"{r['threat_density']:.0%} | {r['cooperation_score']:.2f} | "
            f"{'BP' if r['bulletproof_flag'] else ''} | "
            f"{r['top_ports']} | {r['top_botnet_fams']} | "
            f"{r['top_probe_tags']} | `{r['risk_grade']}` | "
            f"{r['block_recommend']} |"
        )
    (OUT_DIR / "asnintel.md").write_text("\n".join(md) + "\n")
    print(f"[asnintel] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    return run(argparse.Namespace())


if __name__ == "__main__":
    sys.exit(main())

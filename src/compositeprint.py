#!/usr/bin/env python3
"""
compositeprint - multi-dimensional cluster fingerprints in adaptive windows.

Every dimension of a source's behavior already has a producer in this tool
(chainfp for the proto/port choreography + timing, ja4plus for the TLS/HTTP/SSH
client, fingerprint for the stack, campaign/trafficprint for payload, etc.).
What was missing is the FUSION: one canonical fingerprint per (source, episode)
that binds those dimensions together and -- critically -- splits a behavioral
CORE (infrastructure-independent) from CONTEXT (the ASN/CIDR/IP that rotates).

This is Phase 1: build the fused per-episode fingerprint.  Later phases cluster
on it within windows (exact core_hash, then actorlink's graph for fuzzy
neighbours) and track a core_hash as it migrates across infrastructure.

Adaptive episode
----------------
The window is not a fixed clock interval; it is each source's own activity
episode, bounded by its 80th-percentile inter-packet gap -- exactly chainfp's
adaptive session boundary.  An IP active in two campaigns separated by a long
idle gap yields two episodes, each fingerprinted independently.  The episode
build mirrors chainfp's SQL sessionizer (gap -> boundary -> running-sum sid)
and reuses its token grammar, so seq/tempo here are bit-compatible with chainfp.

The core_hash
-------------
    core_hash = md5( stack | seq | tempo | app | payload )

  - stack   : TTL bucket, TCP window mode, proto-mix deciles, SYN/payload rate
  - seq     : the chainfp `chain` (flag-mask + proto + port choreography)
  - tempo   : the chainfp `tchain` (per-source-normalized inter-token cadence)
  - app     : JA4 / JA4H / JA4SSH (most frequent per IP, from ja4plus)
  - payload : dominant payload SHA-256 prefix + has-payload flag

ASN / CIDR / IP / country are carried as CONTEXT columns and are deliberately
NOT in the hash, so the SAME behaviour from a rotated IP produces the SAME
core_hash -- that collision across infrastructure is the whole point.

Memory is bounded the same way chainfp bounds it: one pass partitions the
windowed packets evenly by hash(src_ip) into a spill dir, then each bucket's
episodes are built one at a time (each IP wholly in one bucket -> exact).
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib
from chainfp import _TOKEN_SQL   # reuse the exact sensorChain.pl token grammar


# How many hash(src_ip) buckets to split the packet stream into.  Same knob
# shape as chainfp; bigger = lower peak memory, more parquet parts.
N_BUCKETS   = max(1, int(os.environ.get("SG_COMPOSITE_BUCKETS", "256")))
MIN_PKTS    = 2     # an episode needs >= 2 packets to have a sequence at all
MAX_TOKENS  = 30    # cap the chain head, matching chainfp's diagnostic window


CLUSTER_SCHEMA = pa.schema([
    ("core_hash",      pa.string()),
    ("tier",           pa.string()),
    ("cross_infra",    pa.bool_()),
    ("n_ips",          pa.uint32()),
    ("n_episodes",     pa.uint64()),
    ("n_asns",         pa.uint32()),
    ("n_cidrs",        pa.uint32()),
    ("n_countries",    pa.uint16()),
    ("total_packets",  pa.uint64()),
    ("first_seen",     pa.timestamp("us", tz="UTC")),
    ("last_seen",      pa.timestamp("us", tz="UTC")),
    ("span_hours",     pa.float32()),
    ("present",        pa.string()),
    ("dom_proto",      pa.string()),
    ("rep_port",       pa.uint16()),
    ("seq_chain",      pa.string()),
    ("tempo_chain",    pa.string()),
    ("stack_token",    pa.string()),
    ("ja4",            pa.string()),
    ("ja4h",           pa.string()),
    ("ja4ssh",         pa.string()),
    ("sample_ips",     pa.string()),
    ("sample_asns",    pa.string()),
])


def _cluster_tier(n_ips: int) -> str:
    """Coarse size class for a behavioral cluster (IPs sharing one core_hash)."""
    if n_ips >= 50: return "background"
    if n_ips >= 10: return "broad"
    if n_ips >= 3:  return "campaign"
    return "pair"


def _cidr_of(ip: str) -> str | None:
    """The source's network block: /24 for IPv4, /64 for IPv6.  Matches
    cluster_packets._cidr_of so context lines up with the clustered dataset."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


def _bucket_sql(where: str, packets_from: str) -> str:
    """Full per-bucket episode-fingerprint query.

    Builds adaptive episodes (chainfp's gap/threshold/sid pipeline), aggregates
    every packet-derivable dimension per (src_ip, episode), joins the per-IP app
    fingerprints (ja4_ip) and geo context (geo_ip), and emits one fused row per
    episode with the infrastructure-independent ``core_hash``.
    """
    ttl_bucket = ("(CASE WHEN s.ttl_mode IS NULL THEN 0 "
                  "WHEN s.ttl_mode <= 32 THEN 32 "
                  "WHEN s.ttl_mode <= 64 THEN 64 "
                  "WHEN s.ttl_mode <= 128 THEN 128 ELSE 255 END)")
    return f"""
        WITH base AS (
            SELECT src_ip, ts, proto, dst_port, icmp_type, icmp_code,
                   ttl, tcp_win, tcp_flags, payload_len, payload_sha256, l7_proto,
                   ({_TOKEN_SQL}) AS token
            FROM {packets_from} WHERE {where}
        ),
        gapped AS (
            SELECT *, epoch_us(ts) - epoch_us(lag(ts) OVER w) AS gap_us
            FROM base
            -- (ts, token) is a TOTAL order so packets sharing a microsecond ts
            -- are ordered deterministically; without the tiebreak the chain/
            -- tchain string_aggs (and thus core_hash) jittered across runs.
            WINDOW w AS (PARTITION BY src_ip ORDER BY ts, token)
        ),
        thr AS (
            SELECT src_ip,
                   greatest(2000000.0,
                            coalesce(quantile_cont(gap_us, 0.80), 60000000.0))
                       AS thr_us
            FROM gapped
            WHERE gap_us IS NOT NULL
            GROUP BY src_ip
            HAVING count(*) + 1 >= {MIN_PKTS}
        ),
        bounded AS (
            SELECT g.*,
                   -- Tempo gap at TIMESTAMP granularity: all packets sharing a
                   -- microsecond ts get the same gap (gap from the previous
                   -- distinct ts), so the tempo tag is invariant to the arbitrary
                   -- order of same-ts packets and tchain/core_hash are reproducible.
                   max(g.gap_us) OVER (PARTITION BY g.src_ip, g.ts) AS tgap_us,
                   CASE WHEN g.gap_us IS NULL
                          OR g.gap_us > coalesce(thr.thr_us, 60000000.0)
                        THEN 1 ELSE 0 END AS boundary
            FROM gapped g LEFT JOIN thr USING (src_ip)
        ),
        srcbase AS (
            SELECT src_ip, median(tgap_us) AS base_us
            FROM bounded WHERE boundary = 0 AND tgap_us IS NOT NULL
            GROUP BY src_ip
        ),
        tok AS (
            SELECT b.*, sb.base_us,
                   sum(b.boundary) OVER (PARTITION BY b.src_ip ORDER BY b.ts, b.token
                                         ROWS UNBOUNDED PRECEDING) AS sid
            FROM bounded b LEFT JOIN srcbase sb USING (src_ip)
        ),
        toks AS (
            SELECT *,
                   row_number() OVER (PARTITION BY src_ip, sid ORDER BY ts, token) AS trn,
                   -- Per-value frequencies within the episode, so the modal
                   -- stack/payload fields below can be picked deterministically
                   -- (most frequent, ties broken on the value itself).  Plain
                   -- mode() resolves frequency ties arbitrarily -> core_hash jitter.
                   count(*) OVER (PARTITION BY src_ip, sid, ttl)            AS ttl_n,
                   count(*) OVER (PARTITION BY src_ip, sid, tcp_win)        AS win_n,
                   count(*) OVER (PARTITION BY src_ip, sid, dst_port)       AS port_n,
                   count(*) OVER (PARTITION BY src_ip, sid, payload_sha256) AS pay_n,
                   -- 's' = the session-start ts-group (every packet at the
                   -- session's first ts), not the single boundary row, so the
                   -- tempo tag is invariant to same-ts packet ordering.
                   CASE WHEN base_us IS NULL OR base_us = 0
                            OR ts = min(ts) OVER (PARTITION BY src_ip, sid)
                            THEN 's'
                        WHEN tgap_us < 0.5  * base_us THEN '0'
                        WHEN tgap_us < 2.0  * base_us THEN '1'
                        WHEN tgap_us < 10.0 * base_us THEN '2'
                        ELSE '3' END AS tgb
            FROM tok
        ),
        sess AS (
            SELECT src_ip, sid,
                   string_agg(CASE WHEN trn <= {MAX_TOKENS} THEN token END,
                              ',' ORDER BY ts, token) AS chain,
                   string_agg(CASE WHEN trn <= {MAX_TOKENS}
                                   THEN token || '~' || tgb END,
                              ',' ORDER BY ts, token) AS tchain,
                   count(*)::UBIGINT                        AS pkt_count,
                   min(ts) AS first_seen, max(ts) AS last_seen,
                   arg_max(ttl,     struct_pack(c := ttl_n,  v := ttl))     AS ttl_mode,
                   arg_max(tcp_win, struct_pack(c := win_n,  v := tcp_win)) AS win_mode,
                   count(*) FILTER (WHERE proto = 6)        AS tcp_n,
                   count(*) FILTER (WHERE proto = 17)       AS udp_n,
                   count(*) FILTER (WHERE proto = 1)        AS icmp_n,
                   count(*) FILTER (WHERE tcp_flags = 2)    AS syn_n,
                   count(*) FILTER (WHERE payload_len > 0)  AS payload_n,
                   least(count(DISTINCT dst_port), 65535)::UINTEGER AS port_count,
                   arg_max(dst_port, struct_pack(c := port_n, v := dst_port)) AS top_port,
                   arg_max(payload_sha256, struct_pack(c := pay_n, v := payload_sha256))
                       FILTER (WHERE payload_len > 0
                                 AND payload_sha256 IS NOT NULL)  AS dom_payload
            FROM toks
            GROUP BY src_ip, sid
            HAVING count(*) >= {MIN_PKTS}
        ),
        assembled AS (
            SELECT s.*,
                   j.ja4, j.ja4h, j.ja4ssh,
                   g.asn, g.cidr, g.country_iso,
                   ('ttl' || {ttl_bucket}
                       || '_win' || coalesce(s.win_mode, 0)::VARCHAR
                       || '_t' || round(10.0 * s.tcp_n     / s.pkt_count)::INT::VARCHAR
                       || '_u' || round(10.0 * s.udp_n     / s.pkt_count)::INT::VARCHAR
                       || '_i' || round(10.0 * s.icmp_n    / s.pkt_count)::INT::VARCHAR
                       || '_s' || round(10.0 * s.syn_n     / s.pkt_count)::INT::VARCHAR
                       || '_p' || round(10.0 * s.payload_n / s.pkt_count)::INT::VARCHAR
                   ) AS stack_token,
                   concat_ws(';', coalesce(j.ja4, ''), coalesce(j.ja4h, ''),
                             coalesce(j.ja4ssh, '')) AS app_token,
                   (j.ja4 IS NOT NULL OR j.ja4h IS NOT NULL
                        OR j.ja4ssh IS NOT NULL) AS app_present,
                   (coalesce(substr(lower(hex(s.dom_payload)), 1, 16), '')
                       || CASE WHEN s.payload_n > 0 THEN '/P' ELSE '/-' END
                   ) AS pay_token,
                   (CASE WHEN s.tcp_n >= s.udp_n AND s.tcp_n >= s.icmp_n THEN 'TCP'
                         WHEN s.udp_n >= s.icmp_n THEN 'UDP'
                         ELSE 'ICMP' END) AS dom_proto
            FROM sess s
            LEFT JOIN ja4_ip j USING (src_ip)
            LEFT JOIN geo_ip g USING (src_ip)
        )
        SELECT
            src_ip,
            sid::UINTEGER                                   AS episode_id,
            first_seen, last_seen, pkt_count,
            md5(concat_ws('|', stack_token, coalesce(chain, ''),
                          coalesce(tchain, ''), app_token, pay_token)) AS core_hash,
            concat(CASE WHEN app_present THEN 'a' ELSE '-' END,
                   CASE WHEN payload_n > 0 THEN 'p' ELSE '-' END) AS present,
            substr(chain, 1, 512)                           AS seq_chain,
            substr(tchain, 1, 512)                          AS tempo_chain,
            stack_token,
            ja4, ja4h, ja4ssh,
            dom_proto,
            top_port,
            port_count,
            CASE WHEN dom_payload IS NOT NULL
                 THEN substr(lower(hex(dom_payload)), 1, 64) END AS dom_payload_sha,
            (payload_n > 0)                                 AS has_payload,
            asn, cidr, country_iso
        FROM assembled
    """


def _build_ja4_table(con) -> None:
    """Per-IP app fingerprints (most frequent JA4/JA4H/JA4SSH).  Empty table if
    ja4plus hasn't run, so the LEFT JOIN just yields NULL app tokens."""
    ja4_path = lib.REPORTS / "ja4plus" / "ja4plus.parquet"
    if ja4_path.exists():
        # Pick the most frequent fingerprint of each type per IP, breaking
        # count ties deterministically on the fingerprint string (rn=1 leaves
        # exactly one row per (src_ip, fp_type)).  max_by alone resolves ties
        # arbitrarily, which jittered the fused core_hash across runs.
        con.execute(f"""
            CREATE TEMP TABLE ja4_ip AS
            WITH ranked AS (
                SELECT src_ip, fp_type, fingerprint,
                       row_number() OVER (PARTITION BY src_ip, fp_type
                                          ORDER BY count DESC, fingerprint ASC) AS rn
                FROM read_parquet('{ja4_path.as_posix()}')
                WHERE fp_type IN ('ja4', 'ja4h', 'ja4ssh')
            )
            SELECT src_ip,
                   any_value(fingerprint) FILTER (WHERE fp_type = 'ja4'    AND rn = 1) AS ja4,
                   any_value(fingerprint) FILTER (WHERE fp_type = 'ja4h'   AND rn = 1) AS ja4h,
                   any_value(fingerprint) FILTER (WHERE fp_type = 'ja4ssh' AND rn = 1) AS ja4ssh
            FROM ranked
            GROUP BY src_ip
        """)
        n = con.execute("SELECT count(*) FROM ja4_ip").fetchone()[0]
        print(f"[compositeprint] ja4plus: {n:,} IPs with app fingerprints",
              file=sys.stderr)
    else:
        con.execute("CREATE TEMP TABLE ja4_ip "
                    "(src_ip VARCHAR, ja4 VARCHAR, ja4h VARCHAR, ja4ssh VARCHAR)")
        print("[compositeprint] ja4plus.parquet absent; app dimension empty",
              file=sys.stderr)


def _build_geo_table(con, where: str) -> None:
    """ASN / CIDR / country context per distinct source IP.  These are the
    rotating-infrastructure columns -- carried alongside the fingerprint, never
    folded into core_hash."""
    ips = [r[0] for r in con.execute(
        f"SELECT DISTINCT src_ip FROM packets WHERE {where}").fetchall()]
    print(f"[compositeprint] geo-resolving {len(ips):,} distinct source IPs...",
          file=sys.stderr)
    geo = lib.GeoLookup()
    src, asn, cidr, ciso = [], [], [], []
    for ip in ips:
        rec = geo.lookup(ip)
        src.append(ip)
        asn.append(rec.asn)
        cidr.append(_cidr_of(ip))
        ciso.append(rec.country_iso)
    geo.close()
    tbl = pa.table({
        "src_ip":      pa.array(src, pa.string()),
        "asn":         pa.array(asn, pa.uint32()),
        "cidr":        pa.array(cidr, pa.string()),
        "country_iso": pa.array(ciso, pa.string()),
    })
    con.register("geo_ip_arrow", tbl)
    con.execute("CREATE TEMP TABLE geo_ip AS SELECT * FROM geo_ip_arrow")
    con.unregister("geo_ip_arrow")


def _build_clusters(con, composite_path: Path, out_dir: Path) -> int:
    """Phase 2a: exact within-window clustering on core_hash.

    Groups the per-episode fingerprints into behavioral clusters -- one row per
    core_hash shared by >= 2 source IPs.  Because a core_hash maps to exactly
    one (stack|seq|tempo|app|payload) tuple (proven in Phase 1), the
    representative tokens are unambiguous (any_value is exact).  The headline
    column is ``cross_infra``: a cluster spanning >= 2 ASNs or CIDRs is one
    behaviour deployed across rotated infrastructure.

    Singletons (one IP) are intentionally excluded -- they are not clusters and
    remain available in composite.parquet.
    """
    # Roll up BUCKETED by hash(core_hash): at full corpus there are hundreds of
    # millions of episodes and tens of millions of distinct core_hashes, so a
    # single GROUP BY core_hash OOMs.  Each core_hash hashes to exactly one
    # bucket, so per-bucket rollup is exact and bounds the hash table to 1/M.
    # All sample aggregates are BOUNDED (arg_max top-N, not an unbounded ordered
    # list) and deterministic (struct ordering = volume, ties broken on value).
    m = max(1, int(os.environ.get("SG_COMPOSITE_AGG_BUCKETS", "8")))
    print(f"[compositeprint] clustering episodes by core_hash ({m} buckets)...",
          file=sys.stderr)
    rows = []
    for j in range(m):
        rows += con.execute(f"""
            WITH per_ip AS (
                SELECT core_hash, src_ip,
                       sum(pkt_count)            AS ip_pkts,
                       count(*)                  AS ip_eps,
                       min(first_seen)           AS ip_first,
                       max(last_seen)            AS ip_last,
                       any_value(asn)            AS asn,
                       any_value(cidr)           AS cidr,
                       any_value(country_iso)    AS ciso,
                       any_value(seq_chain)      AS seq,
                       any_value(tempo_chain)    AS tempo,
                       any_value(stack_token)    AS stack,
                       any_value(present)        AS present,
                       any_value(dom_proto)      AS dom_proto,
                       any_value(top_port)       AS top_port,
                       any_value(ja4)            AS ja4,
                       any_value(ja4h)           AS ja4h,
                       any_value(ja4ssh)         AS ja4ssh
                FROM read_parquet('{composite_path.as_posix()}')
                WHERE (hash(core_hash) % {m}) = {j}
                GROUP BY core_hash, src_ip
            )
            SELECT core_hash,
                   count(*)                          AS n_ips,
                   sum(ip_eps)                       AS n_episodes,
                   count(DISTINCT asn)               AS n_asns,
                   count(DISTINCT cidr)              AS n_cidrs,
                   count(DISTINCT ciso)              AS n_countries,
                   sum(ip_pkts)                      AS total_packets,
                   min(ip_first)                     AS first_seen,
                   max(ip_last)                      AS last_seen,
                   any_value(present)                AS present,
                   any_value(dom_proto)              AS dom_proto,
                   arg_max(top_port, struct_pack(p := ip_pkts, v := top_port)) AS rep_port,
                   any_value(seq)                    AS seq_chain,
                   any_value(tempo)                  AS tempo_chain,
                   any_value(stack)                  AS stack_token,
                   any_value(ja4)                    AS ja4,
                   any_value(ja4h)                   AS ja4h,
                   any_value(ja4ssh)                 AS ja4ssh,
                   -- Bounded + deterministic display samples: top IPs by packet
                   -- volume (ties on src_ip), and distinct ASNs of the top IPs.
                   array_to_string(
                       arg_max(src_ip, struct_pack(p := ip_pkts, v := src_ip), 12),
                       ',') AS sample_ips,
                   array_to_string(
                       list_distinct(arg_max(asn, struct_pack(p := ip_pkts, v := asn), 8)),
                       ',') AS sample_asns
            FROM per_ip
            GROUP BY core_hash
            HAVING count(*) >= 2
        """).fetchall()

    cols = ["core_hash", "n_ips", "n_episodes", "n_asns", "n_cidrs",
            "n_countries", "total_packets", "first_seen", "last_seen",
            "present", "dom_proto", "rep_port", "seq_chain", "tempo_chain",
            "stack_token", "ja4", "ja4h", "ja4ssh", "sample_ips", "sample_asns"]
    clusters: list[dict] = []
    for r in rows:
        d = dict(zip(cols, r))
        n_ips = int(d["n_ips"])
        n_asns = int(d["n_asns"] or 0)
        n_cidrs = int(d["n_cidrs"] or 0)
        span_s = ((d["last_seen"] - d["first_seen"]).total_seconds()
                  if d["first_seen"] and d["last_seen"] else 0.0)
        clusters.append({
            "core_hash":     d["core_hash"],
            "tier":          _cluster_tier(n_ips),
            "cross_infra":   bool(n_asns >= 2 or n_cidrs >= 2),
            "n_ips":         n_ips,
            "n_episodes":    int(d["n_episodes"] or 0),
            "n_asns":        n_asns,
            "n_cidrs":       n_cidrs,
            "n_countries":   int(d["n_countries"] or 0),
            "total_packets": int(d["total_packets"] or 0),
            "first_seen":    d["first_seen"],
            "last_seen":     d["last_seen"],
            "span_hours":    float(span_s / 3600.0),
            "present":       d["present"] or "",
            "dom_proto":     d["dom_proto"] or "",
            "rep_port":      int(d["rep_port"]) if d["rep_port"] is not None else 0,
            "seq_chain":     d["seq_chain"] or "",
            "tempo_chain":   d["tempo_chain"] or "",
            "stack_token":   d["stack_token"] or "",
            "ja4":           d["ja4"],
            "ja4h":          d["ja4h"],
            "ja4ssh":        d["ja4ssh"],
            "sample_ips":    d["sample_ips"] or "",
            "sample_asns":   d["sample_asns"] or "",
        })
    # Most operationally interesting first: behaviour spanning the most
    # infrastructure, then the largest IP cohorts.
    clusters.sort(key=lambda c: (c["cross_infra"], c["n_asns"], c["n_ips"],
                                 c["total_packets"]), reverse=True)

    out_path = out_dir / "clusters.parquet"
    tmp = out_path.with_suffix(".parquet.tmp")
    pq.write_table(pa.Table.from_pylist(clusters, schema=CLUSTER_SCHEMA), tmp,
                   compression="zstd", compression_level=3)
    tmp.replace(out_path)

    cross = [c for c in clusters if c["cross_infra"]]
    md = [
        "# compositeprint clusters - behavioral fingerprints shared across IPs",
        "",
        "_One row per `core_hash` shared by >= 2 source IPs.  `cross_infra` "
        "marks a behaviour seen from >= 2 ASNs or CIDRs -- the same tool/campaign "
        "deployed across rotated infrastructure.  Singletons are excluded._",
        "",
        f"- **{len(clusters):,}** behavioral clusters (>= 2 IPs)",
        f"- **{len(cross):,}** span multiple ASNs/CIDRs (cross-infrastructure)",
        "",
        "## Top cross-infrastructure clusters",
        "",
        "| core_hash | tier | IPs | ASNs | CIDRs | pkts | span_h | present | dst_port | sequence |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for c in clusters[:40]:
        seq = (c["seq_chain"] or "")[:54].replace("|", "\\|")
        md.append(f"| `{c['core_hash'][:12]}` | {c['tier']} | {c['n_ips']} "
                  f"| {c['n_asns']} | {c['n_cidrs']} | {c['total_packets']:,} "
                  f"| {c['span_hours']:.1f} | {c['present']} | {c['rep_port']} "
                  f"| {seq} |")
    (out_dir / "clusters.md").write_text("\n".join(md) + "\n")
    print(f"[compositeprint] {len(clusters):,} clusters "
          f"({len(cross):,} cross-infra); wrote {out_path}", file=sys.stderr)
    return len(clusters)


def run(args: argparse.Namespace) -> int:
    out_dir = lib.REPORTS / "compositeprint"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not os.environ.get("SG_DUCK_TMPDIR"):
        sp = Path(tempfile.gettempdir()) / "compositeprint_duck_spill"
        sp.mkdir(parents=True, exist_ok=True)
        os.environ["SG_DUCK_TMPDIR"] = str(sp)
    spill_dir = Path(os.environ["SG_DUCK_TMPDIR"])
    spill_dir.mkdir(parents=True, exist_ok=True)

    # Size memory to the host (this stage runs serialized) instead of a fixed
    # 8GB; the episode build is heavier than chainfp's.  --memory-limit overrides.
    mem = args.memory_limit or lib.auto_memory_limit(0.4)
    con = lib.duck(memory_limit=mem)
    # The per-bucket episode build runs two ordered string_aggs (chain + tchain)
    # plus several arg_max/holistic aggregates + per-value count windows per
    # (src_ip, sid); those buffer per-thread and aren't fully bounded by
    # memory_limit.  Cap threads to keep the concurrent aggregate buffers in
    # budget.  Env SG_COMPOSITE_THREADS overrides.
    _cap = int(os.environ.get("SG_COMPOSITE_THREADS", "4"))
    con.execute(f"SET threads={max(2, min(_cap, (os.cpu_count() or 4) // 2))}")
    print(f"[compositeprint] memory_limit={mem}, buckets={N_BUCKETS}",
          file=sys.stderr)
    lib.register_views(con)
    since = lib.parse_date_arg(args.since)
    until = lib.parse_date_arg(args.until)
    where = lib.date_predicate("ts", since, until)

    n_pkts = con.execute(
        f"SELECT count(*) FROM packets WHERE {where}").fetchone()[0]
    if n_pkts == 0:
        print("[compositeprint] no packets in window; nothing to do",
              file=sys.stderr)
        lib.Report(name="compositeprint", rows=[], markdown="_(no data)_").write()
        con.close()
        return 0
    print(f"[compositeprint] window has {n_pkts:,} packets", file=sys.stderr)

    _build_ja4_table(con)
    _build_geo_table(con, where)

    # Pass 1: partition windowed packets evenly by hash(src_ip) into a spill dir.
    ipb = spill_dir / "composite_ip_buckets"
    if ipb.exists():
        shutil.rmtree(ipb)
    print(f"[compositeprint] partitioning packets into {N_BUCKETS} "
          f"hash(src_ip) buckets...", file=sys.stderr)
    con.execute(f"""
        COPY (SELECT src_ip, ts, proto, dst_port, icmp_type, icmp_code,
                     ttl, tcp_win, tcp_flags, payload_len, payload_sha256,
                     l7_proto, (hash(src_ip) % {N_BUCKETS})::INT AS sbkt
              FROM packets WHERE {where})
        TO '{ipb.as_posix()}'
        (FORMAT parquet, PARTITION_BY (sbkt), COMPRESSION zstd,
         OVERWRITE_OR_IGNORE)
    """)
    buckets = sorted(int(d.name.split("=", 1)[1]) for d in ipb.glob("sbkt=*"))

    # Pass 2: build fused episode fingerprints one bucket at a time.
    stage = spill_dir / "composite_parts"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True, exist_ok=True)
    print(f"[compositeprint] building episode fingerprints over "
          f"{len(buckets)} buckets...", file=sys.stderr)
    for k in buckets:
        src = f"read_parquet('{ipb.as_posix()}/sbkt={k}/*.parquet')"
        sql = _bucket_sql(where, src)
        con.execute(
            f"COPY ({sql}) TO '{(stage / f'part-{k:04d}.parquet').as_posix()}' "
            f"(FORMAT parquet, COMPRESSION zstd)")

    # Coalesce the parts into one report parquet (episode rows are far fewer
    # than packets, so this final pass is cheap).
    out_path = out_dir / "composite.parquet"
    tmp_out = out_path.with_suffix(".parquet.tmp")
    con.execute(f"""
        COPY (SELECT * FROM read_parquet('{stage.as_posix()}/*.parquet'))
        TO '{tmp_out.as_posix()}' (FORMAT parquet, COMPRESSION zstd,
                                   COMPRESSION_LEVEL 3)
    """)
    tmp_out.replace(out_path)

    # Summary stats for the markdown (and a teaser of the rotation signal).
    stats = con.execute(f"""
        SELECT count(*)                       AS episodes,
               count(DISTINCT src_ip)         AS ips,
               count(DISTINCT core_hash)      AS cores,
               count(*) FILTER (WHERE present LIKE 'a%') AS with_app,
               count(*) FILTER (WHERE has_payload)       AS with_payload
        FROM read_parquet('{out_path.as_posix()}')
    """).fetchone()
    # Phase 2a: roll the per-episode fingerprints up into behavioral clusters
    # (shared core_hash), with the cross-infrastructure view as the headline.
    n_clusters = _build_clusters(con, out_path, out_dir)
    con.close()
    shutil.rmtree(ipb, ignore_errors=True)
    shutil.rmtree(stage, ignore_errors=True)

    episodes, ips, cores, with_app, with_payload = stats
    md = [
        "# compositeprint - fused multi-dimensional cluster fingerprints", "",
        "_One row per (source IP, adaptive episode).  `core_hash` fuses stack + "
        "sequence + tempo + app + payload and is independent of ASN/CIDR/IP, so "
        "the same hash under different infrastructure is behaviour that rotated.  "
        "See `clusters.md` for the per-fingerprint cohorts and the "
        "cross-infrastructure view._",
        "",
        f"- **{episodes:,}** episodes across **{ips:,}** source IPs",
        f"- **{cores:,}** distinct behavioral fingerprints (core_hash)",
        f"- **{n_clusters:,}** of those are shared by >= 2 IPs (see clusters.md)",
        f"- **{with_app:,}** episodes carry an app (TLS/HTTP/SSH) fingerprint",
        f"- **{with_payload:,}** episodes carry payload",
    ]
    (out_dir / "composite.md").write_text("\n".join(md) + "\n")

    print(f"[compositeprint] {episodes:,} episodes, {cores:,} core fingerprints",
          file=sys.stderr)
    print(f"[compositeprint] wrote {out_path}", file=sys.stderr)
    print(f"[compositeprint] wrote {out_dir / 'composite.md'}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    ap.add_argument("--memory-limit", default=None,
                    help="DuckDB memory cap (default: auto, ~40%% of host RAM "
                         "since this stage runs serialized).")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

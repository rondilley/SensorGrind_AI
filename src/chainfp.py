#!/usr/bin/env python3
"""
chainfp - per-IP chain-fingerprint extraction (a.k.a. choreography
detector).

A "chain" is the per-source-IP sequence of `(flag_mask, proto, port)`
tokens within one coherent session.  The token format mirrors the
sensorChain.pl tool described in Dilley & Liston's ListonCon 2023
talk (slides 27-28):

    ****S*-TCP/3389,*A****-TCP/3389,*AP***-TCP/3389,*A***F-TCP/3389,
    *A****-TCP/3389

That's a clean five-step successful banner grab against RDP.

Less clean chains - the *interesting* ones for anomaly work - look like:

    ****S*-TCP/50802,***R**-TCP/50802,***R**-TCP/50802

A SYN followed by two RSTs *from the source*.  No legitimate client
behaves that way; it's a tell for source-spoofing or stack-fingerprint
probing.

The aggregate analyzers in this project (per-IP packet counts, per-IP
port sets) erase choreographic structure.  This stage preserves it.

Streaming algorithm
-------------------
The naive "use DuckDB's hash aggregation" approach falls over at
billion-row scale: hash aggregation cannot spill, and we have tens of
millions of (src_ip, session_id) groups.  Instead this module streams
packets out of DuckDB in time order and maintains a small `active` dict
of currently-open sessions.

For each packet:
  - For each window (adaptive + the three fixed windows): look up the
    source IP's currently-open session for that window.  If the gap
    from the previous packet exceeds the window's threshold, close
    that session (emit its chain) and start a new one.
  - Append the packet's token to the open session (capped at
    `max_tokens_per_session`).

Periodically (every `sweep_seconds` of wallclock progress through the
log), sweep `active` and close any session whose `last_ts` is now
older than 2x the threshold.  This keeps `active` bounded to roughly
the IPs that appeared in the last few sweep intervals.

For a 40-minute window across this corpus, the active working set
is on the order of a few thousand IPs; total memory is a few MB,
regardless of corpus size.  The whole pass scales linearly with
packet count, in a single sort + scan.

Window selection
----------------
The analyzer runs the per-IP adaptive window and three fixed
windows (5m / 20m / 40m) in the same streaming pass, then scores each
by Shannon entropy of its chain frequency distribution.  Higher entropy
= more bits of information per chain = more useful for ranking
anomalies.  The best-SNR window is reported, so the next run knows
which window to default to.

Outputs
-------
- `output/reports/chainfp/chainfp.parquet`: one row per (chain, window)
  with source_count, packet_count, distinct_ports, first_seen, last_seen,
  sample_ips, top_dst_ports, token_count, anomaly_tier.
- `output/reports/chainfp/window_snr.parquet`: per-window entropy and
  the picked-best flag.
- `output/reports/chainfp/chainfp.md`: top-of-tail markdown report.
"""
from __future__ import annotations

import argparse
import math
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib


CHAIN_SCHEMA = pa.schema([
    ("chain",           pa.string()),
    ("window_label",    pa.string()),
    ("source_count",    pa.uint32()),
    ("packet_count",    pa.uint64()),
    ("distinct_ports",  pa.uint32()),
    ("first_seen",      pa.timestamp("us", tz="UTC")),
    ("last_seen",       pa.timestamp("us", tz="UTC")),
    ("sample_ips",      pa.string()),
    ("top_dst_ports",   pa.string()),
    ("token_count",     pa.uint32()),
    ("anomaly_tier",    pa.string()),
])

WINDOW_SNR_SCHEMA = pa.schema([
    ("window_label",        pa.string()),
    ("window_seconds",      pa.uint32()),
    ("distinct_chains",     pa.uint32()),
    ("total_chain_obs",     pa.uint32()),
    ("entropy_bits",        pa.float32()),
    ("median_chain_len",    pa.float32()),
    ("is_best",             pa.bool_()),
])


# Three fixed global windows to sweep for SNR comparison.
WINDOW_SWEEP = [
    ("5m",  300),
    ("20m", 1200),
    ("40m", 2400),
]


# ----------------------------------------------------------------------
# Phase 2: build sessions entirely in DuckDB (no Python per-packet loop)
# ----------------------------------------------------------------------

# Token as a SQL expression, computed vectorized in the engine.  Same shape as
# sensorChain.pl: TCP <flag_mask>-TCP/<port>, UDP UDP/<port>,
# ICMP ICMP/<type>.<code>, else proto-<n>.  TCP flag bits (lib.py):
# URG=32 ACK=16 PSH=8 RST=4 SYN=2 FIN=1.
_TOKEN_SQL = """
CASE
  WHEN proto = 6 THEN
    (CASE WHEN (coalesce(tcp_flags,0) & 32) <> 0 THEN 'U' ELSE '*' END) ||
    (CASE WHEN (coalesce(tcp_flags,0) & 16) <> 0 THEN 'A' ELSE '*' END) ||
    (CASE WHEN (coalesce(tcp_flags,0) &  8) <> 0 THEN 'P' ELSE '*' END) ||
    (CASE WHEN (coalesce(tcp_flags,0) &  4) <> 0 THEN 'R' ELSE '*' END) ||
    (CASE WHEN (coalesce(tcp_flags,0) &  2) <> 0 THEN 'S' ELSE '*' END) ||
    (CASE WHEN (coalesce(tcp_flags,0) &  1) <> 0 THEN 'F' ELSE '*' END) ||
    '-TCP/' || coalesce(dst_port, 0)::VARCHAR
  WHEN proto = 17 THEN 'UDP/' || coalesce(dst_port, 0)::VARCHAR
  WHEN proto = 1  THEN 'ICMP/' || coalesce(icmp_type::VARCHAR, 'x')
                       || '.' || coalesce(icmp_code::VARCHAR, 'x')
  ELSE 'proto-' || proto::VARCHAR
END
"""


def _window_sql(where: str, win_seconds: int | None,
                min_pkts: int, max_tokens: int,
                packets_from: str = "packets") -> str:
    """Build sessions for ONE window (and ONE IP bucket) entirely in SQL.

    Sessionization is a window-function pipeline: gap = ts - lag(ts) per IP;
    a gap over the threshold starts a new session (cumulative sum of the
    boundary flag = session id); then group by (src_ip, session) into one
    chain row.  Adaptive window uses each IP's 80th-pct gap as the threshold
    (computed inline); fixed windows use a constant.  Emits one row per session:
    src_ip, chain, pkt_count, port_count, first_ts, last_ts, top_ports.

    ``packets_from`` is the packet source -- the raw ``packets`` view, or one
    IP bucket of it (a clustered-bucket read_parquet, or a hash(src_ip) subset).
    The window-function/GROUP-BY working set is proportional to the IPs in this
    source, so processing one bucket at a time keeps memory bounded; each IP's
    full history stays in one bucket, so per-bucket sessions are exact.
    """
    # All gap math is in EXACT integer microseconds (epoch_us, BIGINT) -- not
    # float seconds -- so the gap-vs-threshold boundary is deterministic.  The
    # adaptive threshold is each IP's 80th-pct gap, which sits inside its own
    # gap distribution, so float jitter there would flip ~0.2% of session
    # boundaries; integer µs avoids it.
    adaptive = win_seconds is None
    thr_cte = ""
    thr_join = ""
    thr_expr = (f"{int(win_seconds) * 1_000_000}" if not adaptive
                else "coalesce(thr.thr_us, 60000000.0)")
    if adaptive:
        thr_cte = f""",
        thr AS (
            SELECT src_ip,
                   greatest(2000000.0,
                            coalesce(quantile_cont(gap_us, 0.80), 60000000.0))
                       AS thr_us
            FROM gapped
            WHERE gap_us IS NOT NULL
            GROUP BY src_ip
            HAVING count(*) + 1 >= {int(min_pkts)}
        )"""
        thr_join = "LEFT JOIN thr USING (src_ip)"
    return f"""
        WITH base AS (
            SELECT src_ip, ts, dst_port, ({_TOKEN_SQL}) AS token
            FROM {packets_from} WHERE {where}
        ),
        gapped AS (
            SELECT *, epoch_us(ts) - epoch_us(lag(ts) OVER w) AS gap_us
            FROM base
            -- (ts, token) is a TOTAL order: packets sharing a microsecond ts
            -- are ordered deterministically by token, so the chain/tchain
            -- string_aggs and the session-id running sum are reproducible.
            -- ORDER BY ts alone left tied-ts packets in engine-dependent order,
            -- jittering the chain (and thus any fused fingerprint) across runs.
            WINDOW w AS (PARTITION BY src_ip ORDER BY ts, token)
        ){thr_cte},
        bounded AS (
            SELECT g.src_ip, g.ts, g.dst_port, g.token, g.gap_us,
                   -- Tempo gap at TIMESTAMP granularity: every packet sharing a
                   -- microsecond ts gets the same gap (the gap from the previous
                   -- distinct ts = the max row-level gap in the ts-group, since
                   -- the rest are 0).  This makes the tempo tag invariant to the
                   -- arbitrary order of same-ts packets, so tchain is reproducible.
                   max(g.gap_us) OVER (PARTITION BY g.src_ip, g.ts) AS tgap_us,
                   CASE WHEN g.gap_us IS NULL OR g.gap_us > {thr_expr}
                        THEN 1 ELSE 0 END AS boundary
            FROM gapped g {thr_join}
        ),
        -- Per-source tempo baseline = median INTRA-session gap.  Used to
        -- normalize each gap (gap/baseline) so the tempo bucket reflects this
        -- source's own pacing shape, not absolute latency -- network RTT scales
        -- all of a source's gaps ~equally, so the ratio cancels it.  Uses the
        -- ts-granularity gap so the baseline is reproducible too.
        srcbase AS (
            SELECT src_ip, median(tgap_us) AS base_us
            FROM bounded WHERE boundary = 0 AND tgap_us IS NOT NULL
            GROUP BY src_ip
        ),
        tok AS (
            SELECT b.src_ip, b.ts, b.dst_port, b.token, b.boundary, b.tgap_us,
                   sb.base_us,
                   sum(b.boundary) OVER (PARTITION BY b.src_ip ORDER BY b.ts, b.token
                                         ROWS UNBOUNDED PRECEDING) AS sid
            FROM bounded b LEFT JOIN srcbase sb USING (src_ip)
        ),
        toks AS (
            SELECT *,
                   row_number() OVER (PARTITION BY src_ip, sid ORDER BY ts, token) AS trn,
                   -- 's' marks the session-start TS-GROUP (every packet at the
                   -- session's first ts), not the single boundary row, so the
                   -- tag is invariant to the order of same-ts packets at a
                   -- session start -- the last source of tchain non-determinism.
                   CASE WHEN base_us IS NULL OR base_us = 0
                            OR ts = min(ts) OVER (PARTITION BY src_ip, sid)
                            THEN 's'                       -- session start
                        WHEN tgap_us < 0.5  * base_us THEN '0'  -- faster than norm
                        WHEN tgap_us < 2.0  * base_us THEN '1'  -- typical
                        WHEN tgap_us < 10.0 * base_us THEN '2'  -- slower
                        ELSE '3' END AS tgb                -- much slower
            FROM tok
        ),
        pc AS (
            SELECT src_ip, sid, dst_port, count(*) AS c
            FROM toks WHERE dst_port IS NOT NULL
            GROUP BY src_ip, sid, dst_port
        ),
        tp AS (
            SELECT src_ip, sid,
                   array_to_string(list_transform(
                       max_by(struct_pack(p := dst_port, c := c), c, 8),
                       x -> x.p::VARCHAR || ':' || x.c::VARCHAR), ',') AS top_ports
            FROM pc GROUP BY src_ip, sid
        ),
        sess AS (
            SELECT src_ip, sid,
                   string_agg(CASE WHEN trn <= {int(max_tokens)} THEN token END,
                              ',' ORDER BY ts, token) AS chain,
                   string_agg(CASE WHEN trn <= {int(max_tokens)}
                                   THEN token || '~' || tgb END,
                              ',' ORDER BY ts, token) AS tchain,
                   count(*)::UINTEGER                       AS pkt_count,
                   least(count(DISTINCT dst_port), 65535)::USMALLINT AS port_count,
                   min(ts) AS first_ts,
                   max(ts) AS last_ts
            FROM toks
            GROUP BY src_ip, sid
            HAVING count(*) >= 2
        )
        SELECT s.src_ip, s.chain, s.tchain, s.pkt_count, s.port_count,
               s.first_ts, s.last_ts, coalesce(tp.top_ports, '') AS top_ports
        FROM sess s LEFT JOIN tp USING (src_ip, sid)
    """


def _stream_sessions(con, since, until, spill_dir: Path,
                     min_pkts: int, max_tokens: int) -> list[tuple[str, Path]]:
    """Build per-window session parquets via SQL, one EVEN IP bucket at a time.

    Returns [(window_label, sessions_dir)].  DuckDB does the sessionization
    with window functions (no Python per-packet loop).  Memory is bounded by
    bucketing packets on hash(src_ip): one pass partitions the (windowed)
    packets into N evenly-sized buckets on the spill disk, then each window's
    sessions are built one bucket at a time.

    NB: we must NOT reuse the ASN-clustered buckets here -- those are bucketed
    by hash(asn) and are heavily skewed (one mega-ASN bucket was 172M rows,
    20x the average, which OOM'd the window build).  hash(src_ip) is even
    (~1.4x avg) and still keeps each IP's full history in one bucket, so
    sessions are exact.
    """
    where = lib.date_predicate("ts", since, until)
    n = max(1, int(os.environ.get("SG_CHAINFP_BUCKETS", "256")))

    # Pass 1: partition the windowed packets evenly by hash(src_ip) -> spill.
    ipb = spill_dir / "ip_buckets"
    if ipb.exists():
        shutil.rmtree(ipb)
    print(f"[chainfp] partitioning packets into {n} hash(src_ip) buckets...",
          file=sys.stderr)
    con.execute(f"""
        COPY (SELECT src_ip, ts, proto, dst_port, tcp_flags, icmp_type,
                     icmp_code, (hash(src_ip) % {n})::INT AS sbkt
              FROM packets WHERE {where})
        TO '{ipb.as_posix()}'
        (FORMAT parquet, PARTITION_BY (sbkt), COMPRESSION zstd,
         OVERWRITE_OR_IGNORE)
    """)
    buckets = sorted(int(d.name.split("=", 1)[1]) for d in ipb.glob("sbkt=*"))

    # Pass 2: build sessions per window, one bucket at a time (bounded memory).
    windows: list[tuple[str, int | None]] = [("adaptive", None)]
    windows += [(lbl, sec) for lbl, sec in WINDOW_SWEEP]
    out_paths: list[tuple[str, Path]] = []
    for label, win_seconds in windows:
        d = spill_dir / f"sessions_{label}"
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)
        print(f"[chainfp] building sessions ({label}) over {len(buckets)} "
              f"src_ip buckets...", file=sys.stderr)
        for k in buckets:
            src = f"read_parquet('{ipb.as_posix()}/sbkt={k}/*.parquet')"
            sql = _window_sql(where, win_seconds, min_pkts, max_tokens,
                              packets_from=src)
            con.execute(
                f"COPY ({sql}) TO '{(d / f'part-{k:04d}.parquet').as_posix()}' "
                f"(FORMAT parquet, COMPRESSION zstd)")
        out_paths.append((label, d))
    shutil.rmtree(ipb, ignore_errors=True)   # drop the transient packet spill
    print("[chainfp] session build done", file=sys.stderr)
    return out_paths


# ----------------------------------------------------------------------
# Phase 3: aggregate per-session parquet -> per-chain summary
# ----------------------------------------------------------------------

def _aggregate_window(con, label: str, sess_path: Path,
                      max_chain_chars: int,
                      chain_col: str = "chain") -> tuple[list[dict], dict]:
    """Aggregate the streamed per-session parquet into one row per chain.

    ``chain_col`` selects which session column to roll up: "chain" (the
    untimed proto/port choreography) or "tchain" (the timed chain -- same
    sequence with each token annotated by its per-source-normalized inter-
    token gap bucket).  Output schema is identical either way (the rolled-up
    value lands in the "chain" field).  Bucketed by hash to bound memory.

    Returns (chain_rows, snr_row).
    """
    print(f"[chainfp] aggregating {chain_col} ({label})...", file=sys.stderr)
    con.execute(f"""
        CREATE OR REPLACE VIEW sess_{label} AS
        SELECT * FROM read_parquet('{sess_path.as_posix()}/*.parquet')
    """)
    # Roll sessions up to one row per chain, BUCKETED by hash(chain): the
    # GROUP BY (chain, src_ip) then GROUP BY chain over the whole corpus has
    # tens of millions of (long-string chain, src_ip) keys and OOMs at scale.
    # Each chain hashes to exactly one bucket, so per-bucket rollup is exact
    # and bounds the hash-table to 1/M of the chains.  top-N IPs per chain uses
    # max_by(arg, val, n) (bounded heap, spillable) -- not a window/ordered agg.
    m = max(1, int(os.environ.get("SG_CHAINFP_AGG_BUCKETS", "8")))
    rows = []
    for j in range(m):
        rows += con.execute(f"""
            WITH truncated AS (
                SELECT
                  CASE WHEN length({chain_col}) > {max_chain_chars}
                       THEN substring({chain_col}, 1, {max_chain_chars}) || ',...'
                       ELSE {chain_col}
                  END AS chain,
                  src_ip, pkt_count, first_ts, last_ts, top_ports
                FROM sess_{label}
            ),
            bucketed AS (
                SELECT * FROM truncated WHERE (hash(chain) % {m}) = {j}
            ),
            per_ip AS (
                SELECT chain, src_ip,
                       sum(pkt_count)   AS ip_pkts,
                       min(first_ts)    AS ip_first,
                       max(last_ts)     AS ip_last,
                       any_value(top_ports) AS sample_ports
                FROM bucketed GROUP BY chain, src_ip
            )
            SELECT chain,
                   count(*)                       AS source_count,
                   sum(ip_pkts)                   AS packet_count,
                   min(ip_first)                  AS first_seen,
                   max(ip_last)                   AS last_seen,
                   array_to_string(max_by(src_ip, ip_pkts, 25), ',') AS all_ips,
                   max_by(sample_ports, ip_pkts, 1)[1] AS top_dst_ports,
                   (length(chain) - length(replace(chain, ',', '')) + 1)
                                                  AS token_count
            FROM per_ip
            GROUP BY chain
        """).fetchall()

    chain_rows = []
    src_counts = []
    total = 0
    chain_lens = []
    for chain, src_count, pkt_count, ts0, ts1, all_ips, top_ports, tok_count in rows:
        chain_lens.append(int(tok_count or 0))
        total += int(src_count)
        src_counts.append(int(src_count))
        ips = (all_ips or "").split(",")[:8]
        chain_rows.append({
            "chain":           chain,
            "window_label":    label,
            "source_count":    int(src_count),
            "packet_count":    int(pkt_count or 0),
            "distinct_ports":  0,   # filled in by top_dst_ports parse
            "first_seen":      ts0,
            "last_seen":       ts1,
            "sample_ips":      ",".join(ips),
            "top_dst_ports":   top_ports or "",
            "token_count":     int(tok_count or 0),
            "anomaly_tier":    _bucket_tier(int(src_count)),
        })
    chain_rows.sort(key=lambda r: -r["source_count"])

    entropy = 0.0
    if total > 0:
        for n in src_counts:
            p = n / total
            if p > 0:
                entropy -= p * math.log2(p)
    median_len = float(sorted(chain_lens)[len(chain_lens)//2]
                       if chain_lens else 0)
    snr = {
        "window_label":     label,
        "window_seconds":   0,
        "distinct_chains":  int(len(chain_rows)),
        "total_chain_obs":  int(total),
        "entropy_bits":     float(entropy),
        "median_chain_len": median_len,
        "is_best":          False,
    }
    print(f"[chainfp]   {label}: {len(chain_rows):,} distinct chains, "
          f"entropy = {entropy:.2f} bits", file=sys.stderr)
    return chain_rows, snr


def _bucket_tier(n: int) -> str:
    if n >= 1000: return "background"
    if n >= 100:  return "common"
    if n >= 10:   return "distinctive"
    if n >= 2:    return "rare"
    return "singleton"


# ----------------------------------------------------------------------
# Phase 4: markdown report
# ----------------------------------------------------------------------

def _write_markdown(out_path: Path, all_chain_rows: list[dict],
                    snr_rows: list[dict], best_label: str) -> None:
    md = ["# chainfp - per-IP packet choreography fingerprints", ""]
    md.append("_Each chain is a per-source-IP sequence of "
              "`(flag_mask, proto, port)` tokens within one session.  "
              "Token format mirrors `sensorChain.pl` "
              "(Dilley & Liston, ListonCon 2023).  Built in a single "
              "time-sorted streaming pass; memory bounded by the "
              "active-session set, not by corpus size.  The "
              "analyzer runs the per-IP adaptive window and the "
              "5m / 20m / 40m fixed windows in the same pass; the "
              "best-SNR window is picked by Shannon entropy of the "
              "per-chain frequency distribution._")
    md.append("")
    md.append("## Window SNR comparison")
    md.append("")
    md.append("| window | distinct chains | total obs | entropy (bits) "
              "| median chain length | best |")
    md.append("| --- | ---: | ---: | ---: | ---: | :---: |")
    for s in snr_rows:
        mark = "**X**" if s["is_best"] else ""
        md.append(f"| {s['window_label']} | "
                  f"{s['distinct_chains']:,} | "
                  f"{s['total_chain_obs']:,} | "
                  f"{s['entropy_bits']:.2f} | "
                  f"{s['median_chain_len']:.1f} | {mark} |")
    md.append("")

    def _subset(tier: str, n: int):
        rows = [r for r in all_chain_rows
                if r["window_label"] == best_label
                and r["anomaly_tier"] == tier]
        rows.sort(key=lambda r: -r["source_count"])
        return rows[:n]

    md.append(f"## Top 20 background chains (best-SNR window: {best_label})")
    md.append("")
    md.append("_The dominant arrival patterns - what 'normal' inbound "
              "looks like._")
    md.append("")
    md.append("| sources | tokens | chain | top_dst_ports |")
    md.append("| ---: | ---: | --- | --- |")
    for r in _subset("background", 20):
        md.append(f"| {r['source_count']:,} | {r['token_count']} | "
                  f"`{r['chain']}` | {r['top_dst_ports']} |")
    md.append("")

    md.append(f"## Top 50 distinctive chains (10-99 sources, "
              f"best-SNR window: {best_label})")
    md.append("")
    md.append("_Candidate-anomaly chains: produced by a small named "
              "set of sources, cohesive enough to be a toolkit "
              "fingerprint, rare enough not to be background scanning._")
    md.append("")
    md.append("| sources | tokens | chain | top_dst_ports | first_seen | "
              "last_seen |")
    md.append("| ---: | ---: | --- | --- | --- | --- |")
    for r in _subset("distinctive", 50):
        md.append(f"| {r['source_count']} | {r['token_count']} | "
                  f"`{r['chain']}` | {r['top_dst_ports']} | "
                  f"{r['first_seen']} | {r['last_seen']} |")
    md.append("")

    rare = [r for r in all_chain_rows
            if r["window_label"] == best_label
            and r["anomaly_tier"] == "rare"]
    rare.sort(key=lambda r: -r["packet_count"])
    md.append(f"## Top 30 rare chains (2-9 sources, best-SNR window: "
              f"{best_label})")
    md.append("")
    md.append("_Chains from a handful of sources each.  A real client's "
              "standard handshake never lands here; these are the tells._")
    md.append("")
    md.append("| sources | pkts | tokens | chain | top_dst_ports | "
              "sample_ips |")
    md.append("| ---: | ---: | ---: | --- | --- | --- |")
    for r in rare[:30]:
        md.append(f"| {r['source_count']} | {r['packet_count']:,} | "
                  f"{r['token_count']} | `{r['chain']}` | "
                  f"{r['top_dst_ports']} | {r['sample_ips'][:60]} |")
    md.append("")

    out_path.write_text("\n".join(md) + "\n")


# ----------------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    out_dir = lib.REPORTS / "chainfp"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Spill area for intermediate per-window session parquets.
    if not os.environ.get("SG_DUCK_TMPDIR"):
        sp = Path(tempfile.gettempdir()) / "chainfp_duck_spill"
        sp.mkdir(parents=True, exist_ok=True)
        os.environ["SG_DUCK_TMPDIR"] = str(sp)
    spill_dir = Path(os.environ["SG_DUCK_TMPDIR"])
    spill_dir.mkdir(parents=True, exist_ok=True)
    print(f"[chainfp] spill directory: {spill_dir}", file=sys.stderr)

    # Size memory to the host (this stage runs serialized) instead of a fixed
    # 8GB that OOM'd the 1.1B-packet session build; --memory-limit overrides.
    mem = args.memory_limit or lib.auto_memory_limit(0.4)
    con = lib.duck(memory_limit=mem)
    # The session build runs TWO ordered string_aggs per group (chain + the
    # timed tchain) plus a per-source median; those ordered/holistic aggregates
    # buffer per-thread and are not fully bounded by memory_limit (DuckDB's own
    # first OOM hint is "reduce threads").  Cap threads so the concurrent
    # aggregate buffers stay within the limit.  Env SG_CHAINFP_THREADS overrides.
    _cap = int(os.environ.get("SG_CHAINFP_THREADS", "4"))
    con.execute(f"SET threads={max(2, min(_cap, (os.cpu_count() or 4) // 2))}")
    print(f"[chainfp] memory_limit={mem}, buckets={os.environ.get('SG_CHAINFP_BUCKETS', '256')}",
          file=sys.stderr)
    lib.register_views(con)
    since = lib.parse_date_arg(args.since)
    until = lib.parse_date_arg(args.until)

    # Quick existence check.
    n_pkts = con.execute(f"""
        SELECT count(*) FROM packets
        WHERE {lib.date_predicate('ts', since, until)}
    """).fetchone()[0]
    if n_pkts == 0:
        print("[chainfp] no packets in window; nothing to do",
              file=sys.stderr)
        con.close()
        return 0
    print(f"[chainfp] window has {n_pkts:,} packets", file=sys.stderr)

    # Session build (SQL): per-IP adaptive threshold is computed inline in the
    # adaptive window query, so no separate threshold pre-pass is needed.
    sess_paths = _stream_sessions(
        con, since, until, spill_dir,
        min_pkts=args.min_pkts_per_ip,
        max_tokens=args.max_tokens_per_session,
    )

    # Aggregate per window.
    all_chain_rows: list[dict] = []
    snr_rows: list[dict] = []
    window_seconds = {"adaptive": 0}
    for lbl, sec in WINDOW_SWEEP:
        window_seconds[lbl] = sec
    for label, path in sess_paths:
        if not path.exists() or path.stat().st_size == 0:
            continue
        cr, snr = _aggregate_window(con, label, path, args.max_chain_chars)
        snr["window_seconds"] = window_seconds[label]
        snr_rows.append(snr)
        all_chain_rows.extend(cr)

    if not snr_rows:
        print("[chainfp] no chains found; emitting empty output",
              file=sys.stderr)
        con.close()
        return 0

    best = max(snr_rows, key=lambda r: r["entropy_bits"])
    for s in snr_rows:
        s["is_best"] = (s["window_label"] == best["window_label"])
    best_label = best["window_label"]
    print(f"[chainfp] best-SNR window: {best_label} "
          f"({best['entropy_bits']:.2f} bits over "
          f"{best['distinct_chains']:,} distinct chains)",
          file=sys.stderr)

    # Timed chains: roll up ONLY the best-SNR window's sessions by `tchain`
    # (the same proto/port choreography, with each token tagged by its
    # per-source-normalized inter-token gap bucket).  We compute this for the
    # winning window only -- it's the one the correlator consumes, and the
    # timed variant is strictly finer-grained, so its entropy/SNR is reported
    # in its own snr row rather than competing in the window sweep.
    timed_rows: list[dict] = []
    timed_snr: dict | None = None
    best_path = dict(sess_paths).get(best_label)
    if best_path is not None and best_path.exists():
        timed_rows, timed_snr = _aggregate_window(
            con, best_label, best_path, args.max_chain_chars,
            chain_col="tchain")
        timed_snr["window_seconds"] = window_seconds[best_label]
        timed_snr["is_best"] = True

    con.close()

    pq.write_table(pa.Table.from_pylist(all_chain_rows,
                                         schema=CHAIN_SCHEMA),
                   out_dir / "chainfp.parquet",
                   compression="zstd", compression_level=3)
    pq.write_table(pa.Table.from_pylist(snr_rows,
                                         schema=WINDOW_SNR_SCHEMA),
                   out_dir / "window_snr.parquet",
                   compression="zstd", compression_level=3)
    _write_markdown(out_dir / "chainfp.md", all_chain_rows,
                    snr_rows, best_label)
    print(f"[chainfp] wrote {out_dir/'chainfp.parquet'}",
          file=sys.stderr)
    print(f"[chainfp] wrote {out_dir/'window_snr.parquet'}",
          file=sys.stderr)
    print(f"[chainfp] wrote {out_dir/'chainfp.md'}", file=sys.stderr)

    if timed_rows:
        pq.write_table(pa.Table.from_pylist(timed_rows, schema=CHAIN_SCHEMA),
                       out_dir / "chainfp_timed.parquet",
                       compression="zstd", compression_level=3)
        pq.write_table(pa.Table.from_pylist([timed_snr],
                                            schema=WINDOW_SNR_SCHEMA),
                       out_dir / "window_snr_timed.parquet",
                       compression="zstd", compression_level=3)
        print(f"[chainfp] wrote {out_dir/'chainfp_timed.parquet'} "
              f"({len(timed_rows):,} timed chains, "
              f"{timed_snr['entropy_bits']:.2f} bits)", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    lib.add_window_args(ap)
    ap.add_argument("--min-pkts-per-ip", type=int, default=2,
                    help="Minimum packets per src_ip for adaptive "
                         "threshold computation (default 2).")
    ap.add_argument("--max-chain-chars", type=int, default=2048,
                    help="Truncate chains longer than this many "
                         "characters in the aggregation (default 2048).")
    ap.add_argument("--max-tokens-per-session", type=int, default=30,
                    help="Cap per-session chain at this many tokens "
                         "(default 30).  The head of a chain carries "
                         "the diagnostic signal.")
    ap.add_argument("--batch-rows", type=int, default=100_000,
                    help="DuckDB streaming batch size in rows "
                         "(default 100k).")
    ap.add_argument("--memory-limit", default=None,
                    help="DuckDB memory cap (default: auto, ~40%% of host RAM "
                         "since this stage runs serialized).")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

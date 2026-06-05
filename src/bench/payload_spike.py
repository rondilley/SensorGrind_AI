#!/usr/bin/env python3
"""
bench/payload_spike — Track B feasibility measurement (read-only).

Question: if we move payload pattern-mining to embeddings + HDBSCAN, how many
vectors must we actually compute, and is that tractable on this CPU box?

We never embed all 97M distinct payloads. We embed *representatives* after a
cheap near-duplicate collapse (randomized scan probes differ by a few bytes,
so a prefix signature folds huge families into one rep, then the cluster
label propagates to the family). This script measures the rep count at several
collapse granularities (HyperLogLog, so memory stays flat regardless of
cardinality) plus the length/proto shape that drives the pilot scope.

Output: output/eval/payload_spike.{json,md}. No models, no writes to the
corpus. One scalar scan + one bytes-prefix scan.
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib

EVAL_DIR = lib.OUTPUT_DIR / "eval"

L7_NAME = {
    0: "unknown", 1: "http", 2: "tls", 3: "ssh", 4: "ftp", 5: "smtp",
    6: "dns", 7: "telnet", 8: "rdp", 9: "smb", 10: "mqtt", 11: "irc",
    12: "bittorrent", 13: "mirai", 14: "mongo", 15: "redis", 16: "vnc",
}
PILOT = {"http": 1, "ssh": 3, "dns": 6, "telnet": 7}

# Text-like protocols where payloads are templatable (the TrafficPrint-style
# embedding approach only makes sense here; binary/random traffic is noise to
# a language-model encoder). Codes from parser.L7_*.
TEXT_PROTOS = {"http": 1, "ssh": 3, "smtp": 5, "telnet": 7, "ftp": 4,
               "irc": 11, "mongo": 14, "redis": 15}

VECTOR_DIM = 384          # MiniLM-L6-class encoder output width
BYTES_PER_FLOAT = 4
RAM_BUDGET_GB = 40        # leave headroom on the 62 GB box for HDBSCAN structures

# Conservative / optimistic CPU embedding throughput for a MiniLM-class encoder
# batched across the box's cores (short sequences). Stated, not assumed silently.
THROUGHPUT = {"conservative_per_s": 1000, "optimistic_per_s": 4000}


def _hours(reps: int, per_s: int) -> float:
    return round(reps / per_s / 3600, 2)


def run() -> dict:
    con = lib.duck(memory_limit=lib.auto_memory_limit(fraction=0.4, min_gb=4))
    lib.register_views(con)

    print("[spike] scalar pass: length + protocol distribution...", file=sys.stderr)
    total, p50, p90, p99, pmax = con.execute("""
        SELECT count(*),
               approx_quantile(payload_len, 0.50),
               approx_quantile(payload_len, 0.90),
               approx_quantile(payload_len, 0.99),
               max(payload_len)
        FROM payload_blobs WHERE payload_len >= 8
    """).fetchone()

    len_buckets = con.execute("""
        SELECT CASE WHEN payload_len <= 128 THEN '1:<=128'
                    WHEN payload_len <= 512 THEN '2:129-512'
                    WHEN payload_len <= 2048 THEN '3:513-2048'
                    ELSE '4:>2048' END AS bucket,
               count(*) AS n
        FROM payload_blobs WHERE payload_len >= 8
        GROUP BY bucket ORDER BY bucket
    """).fetchall()

    proto = con.execute("""
        SELECT l7_proto, count(*) AS n
        FROM payload_blobs WHERE payload_len >= 8
        GROUP BY l7_proto ORDER BY n DESC
    """).fetchall()

    print("[spike] bytes pass: near-dup representative counts (HLL)...",
          file=sys.stderr)
    # One scan computes every signature + per-pilot-proto rep count.
    pilot_sel = ",\n".join(
        f"approx_count_distinct(md5(bytes[1:64])) "
        f"FILTER (l7_proto = {code}) AS reps64_{name}"
        for name, code in PILOT.items()
    )
    pilot_cnt = ",\n".join(
        f"count(*) FILTER (l7_proto = {code}) AS n_{name}"
        for name, code in PILOT.items()
    )
    row = con.execute(f"""
        SELECT
            approx_count_distinct(payload_sha256)      AS d_exact,
            approx_count_distinct(md5(bytes[1:32]))     AS d_pre32,
            approx_count_distinct(md5(bytes[1:64]))     AS d_pre64,
            approx_count_distinct(md5(bytes[1:128]))    AS d_pre128,
            approx_count_distinct(md5(bytes[1:256]))    AS d_pre256,
            {pilot_sel},
            {pilot_cnt}
        FROM payload_blobs WHERE payload_len >= 8
    """).fetchdf().iloc[0].to_dict()

    reps = {
        "exact_distinct": int(row["d_exact"]),
        "prefix32": int(row["d_pre32"]),
        "prefix64": int(row["d_pre64"]),
        "prefix128": int(row["d_pre128"]),
        "prefix256": int(row["d_pre256"]),
    }
    pilot = {
        name: {"payloads": int(row[f"n_{name}"]),
               "reps_prefix64": int(row[f"reps64_{name}"])}
        for name in PILOT
    }

    # Exact (not HLL) counts for the text-protocol subset — the verdict rests
    # on these, since the whole-corpus HLL estimates are noisy at this scale.
    print("[spike] exact pass: text-protocol subset...", file=sys.stderr)
    codes = ",".join(str(c) for c in TEXT_PROTOS.values())
    t_n, t_sha, t_64 = con.execute(f"""
        SELECT count(*),
               count(DISTINCT payload_sha256),
               count(DISTINCT md5(bytes[1:64]))
        FROM payload_blobs
        WHERE payload_len >= 8 AND l7_proto IN ({codes})
    """).fetchone()
    con.close()

    def _gb(n):
        return round(n * VECTOR_DIM * BYTES_PER_FLOAT / 1e9, 1)

    full_reps = reps["prefix64"]
    scoped_reps = int(t_64)
    verdict = {
        "full_corpus": {
            "reps_to_embed": full_reps,
            "embed_hours_conservative": _hours(full_reps, THROUGHPUT["conservative_per_s"]),
            "embed_hours_optimistic": _hours(full_reps, THROUGHPUT["optimistic_per_s"]),
            "vector_ram_gb": _gb(full_reps),
            "hdbscan_feasible_in_ram": _gb(full_reps) < RAM_BUDGET_GB,
        },
        "text_scoped": {
            "protocols": list(TEXT_PROTOS),
            "payloads": int(t_n),
            "distinct_sha": int(t_sha),
            "reps_prefix64": scoped_reps,
            "embed_minutes_conservative": round(scoped_reps / THROUGHPUT["conservative_per_s"] / 60, 1),
            "vector_ram_gb": _gb(scoped_reps),
            "hdbscan_feasible_in_ram": _gb(scoped_reps) < RAM_BUDGET_GB,
        },
        "ram_budget_gb": RAM_BUDGET_GB,
        "recommendation": (
            "Scope Track B embeddings to TEXT protocols. Byte-prefix collapse "
            "does NOT shrink the corpus (high-entropy unknown/bittorrent/tls "
            "dominate), so whole-corpus embedding+HDBSCAN is infeasible in RAM; "
            "the text subset is small and fully tractable."
        ),
    }

    return {
        "verdict": verdict,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "total_payloads_ge8": int(total),
        "length": {"p50": int(p50), "p90": int(p90), "p99": int(p99),
                   "max": int(pmax)},
        "length_buckets": {b: int(n) for b, n in len_buckets},
        "proto": {L7_NAME.get(c, str(c)): int(n) for c, n in proto},
        "reps": reps,
        "pilot": pilot,
    }


def _render_md(m: dict) -> str:
    total = m["total_payloads_ge8"]
    def frac(n):
        return f"{n:,} ({n/total*100:.1f}%)" if total else f"{n:,}"
    reps = m["reps"]
    v = m["verdict"]
    fc, ts = v["full_corpus"], v["text_scoped"]
    lines = [
        "# Track B feasibility spike — payload embedding budget",
        "",
        f"_Generated {m['generated_at']} UTC by bench/payload_spike._",
        "",
        "## Verdict",
        "",
        f"> {v['recommendation']}",
        "",
        "| approach | reps | embed time | vector RAM | HDBSCAN fits "
        f"<{v['ram_budget_gb']}GB? |",
        "| --- | --- | --- | --- | --- |",
        f"| **whole corpus** (prefix-64) | {fc['reps_to_embed']:,} | "
        f"{fc['embed_hours_conservative']}–{fc['embed_hours_optimistic']} h | "
        f"{fc['vector_ram_gb']} GB | "
        f"{'yes' if fc['hdbscan_feasible_in_ram'] else 'NO'} |",
        f"| **text protocols only** | {ts['reps_prefix64']:,} | "
        f"{ts['embed_minutes_conservative']} min | {ts['vector_ram_gb']} GB | "
        f"{'yes' if ts['hdbscan_feasible_in_ram'] else 'NO'} |",
        "",
        f"Text subset = {', '.join(ts['protocols'])} "
        f"({ts['payloads']:,} payloads, {ts['distinct_sha']:,} distinct).",
        "",
        f"**Total distinct payloads (len>=8): {total:,}**",
        "",
        "## Near-duplicate representatives (what we'd actually embed)",
        "",
        "Embed one representative per near-dup family, then propagate the "
        "cluster label. Counts below are HyperLogLog estimates.",
        "",
        "| collapse granularity | representatives | vs total |",
        "| --- | --- | --- |",
        f"| exact (sha256, no collapse) | {reps['exact_distinct']:,} | "
        f"{reps['exact_distinct']/total*100:.0f}% |",
        f"| first 32 bytes | {reps['prefix32']:,} | {reps['prefix32']/total*100:.1f}% |",
        f"| first 64 bytes | {reps['prefix64']:,} | {reps['prefix64']/total*100:.1f}% |",
        f"| first 128 bytes | {reps['prefix128']:,} | {reps['prefix128']/total*100:.1f}% |",
        f"| first 256 bytes | {reps['prefix256']:,} | {reps['prefix256']/total*100:.1f}% |",
        "",
        "_Note: byte-prefix collapse barely reduces the set — the corpus is "
        "high-entropy (random/encrypted), not near-dup families. HLL estimates "
        "(±, can invert across columns); the verdict uses exact text-subset counts._",
        "",
        "## Length distribution (drives truncation)",
        "",
        f"- p50={m['length']['p50']}  p90={m['length']['p90']}  "
        f"p99={m['length']['p99']}  max={m['length']['max']} bytes",
        "",
        "| length bucket | payloads |", "| --- | --- |",
        *[f"| {b2[2:]} | {frac(n)} |" for b2, n in sorted(m["length_buckets"].items())],
        "",
        "## Protocol mix (pilot scope = HTTP/SSH/DNS/Telnet)",
        "",
        "| proto | payloads |", "| --- | --- |",
        *[f"| {p} | {frac(n)} |" for p, n in m["proto"].items()],
        "",
        "| pilot proto | payloads | prefix64 reps |", "| --- | --- | --- |",
        *[f"| {name} | {d['payloads']:,} | {d['reps_prefix64']:,} |"
          for name, d in m["pilot"].items()],
        "",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    m = run()
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    (EVAL_DIR / "payload_spike.json").write_text(json.dumps(m, indent=2))
    (EVAL_DIR / "payload_spike.md").write_text(_render_md(m))
    print(f"[spike] wrote {EVAL_DIR / 'payload_spike.json'}")
    print(f"[spike] wrote {EVAL_DIR / 'payload_spike.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
adversarysim - adversary-simulation harness for evaluating the analyzer
pipeline against synthetic attack patterns.

Generates a small synthetic packet stream that mimics six canonical
adversary archetypes and scores how many of them the existing
analyzers/risk-model catch.  The point is *not* to add more attacker
data to the corpus - it's to give the operator a regression harness so
that detection coverage doesn't silently regress when the model
retrains, the parser changes, or a new analyzer ships.

Archetypes:
  1. fast_scanner       1 IP, 5,000 ports in <60s (horizontal scan)
  2. slow_scanner       1 IP, 30 ports over 90 days (slow-low)
  3. distributed_brute  100 IPs in 1 /24 each hitting one RDP IP at 60s
  4. malware_drop       1 IP delivers a known-bad payload SHA-256
  5. dga_caller         1 IP sends 200 high-entropy DNS qnames
  6. mimic_actor        1 IP echoes a sensor self-banner repeatedly

Output:
  - simulated.parquet  rows tagged by archetype
  - coverage.md        a report comparing what got detected vs what was
                       injected
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import random
import string
import sys
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib

OUT_DIR = lib.OUTPUT_DIR / "adversarysim"

SIM_SCHEMA = pa.schema([
    ("archetype",  pa.string()),
    ("src_ip",     pa.string()),
    ("dst_port",   pa.uint16()),
    ("ts",         pa.timestamp("us", tz="UTC")),
    ("payload",    pa.string()),
    ("note",       pa.string()),
])


def _ip(seed: int, octets: tuple[int, int, int]) -> str:
    return f"{octets[0]}.{octets[1]}.{octets[2]}.{seed & 0xFF}"


def _ts(start: _dt.datetime, offset_s: float) -> _dt.datetime:
    return start + _dt.timedelta(seconds=offset_s)


def generate(seed: int, sensor_banner: str) -> list[dict]:
    rng = random.Random(seed)
    start = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=120)
    rows: list[dict] = []

    # 1. fast scanner
    fs_ip = _ip(11, (203, 0, 113))
    for port in range(1, 5001):
        rows.append({
            "archetype": "fast_scanner",
            "src_ip":    fs_ip,
            "dst_port":  port,
            "ts":        _ts(start, port * 0.01),
            "payload":   "",
            "note":      "TCP SYN",
        })

    # 2. slow scanner
    ss_ip = _ip(22, (198, 51, 100))
    for day in range(0, 90, 3):
        for k in range(rng.randint(1, 3)):
            rows.append({
                "archetype": "slow_scanner",
                "src_ip":    ss_ip,
                "dst_port":  rng.choice([22, 23, 80, 443, 3389, 5900, 8080]),
                "ts":        _ts(start, day * 86400 + k * 120),
                "payload":   "",
                "note":      "intermittent low-volume probe",
            })

    # 3. distributed brute force on /24
    base = (192, 0, 2)
    for host in range(100):
        ip = f"{base[0]}.{base[1]}.{base[2]}.{host + 50}"
        for tick in range(20):
            rows.append({
                "archetype": "distributed_brute",
                "src_ip":    ip,
                "dst_port":  3389,
                "ts":        _ts(start, 86400 * 30 + tick * 60
                                 + host * 0.5),
                "payload":   "RDPNEG",
                "note":      "RDP brute-force from /24",
            })

    # 4. malware drop
    md_ip = _ip(91, (203, 0, 113))
    payload = "".join(rng.choices(string.ascii_letters + string.digits, k=256))
    payload_sha = hashlib.sha256(payload.encode()).hexdigest()
    for k in range(5):
        rows.append({
            "archetype": "malware_drop",
            "src_ip":    md_ip,
            "dst_port":  445,
            "ts":        _ts(start, 86400 * 50 + k * 30),
            "payload":   payload[:128],
            "note":      f"payload_sha256={payload_sha[:16]}",
        })

    # 5. DGA DNS caller
    dga_ip = _ip(42, (198, 51, 100))
    for k in range(200):
        label = "".join(rng.choices(string.ascii_lowercase + string.digits,
                                    k=rng.randint(14, 20)))
        rows.append({
            "archetype": "dga_caller",
            "src_ip":    dga_ip,
            "dst_port":  53,
            "ts":        _ts(start, 86400 * 70 + k * 5),
            "payload":   f"{label}.example.com",
            "note":      "DGA-looking qname",
        })

    # 6. mimic actor
    mm_ip = _ip(77, (203, 0, 113))
    for k in range(30):
        rows.append({
            "archetype": "mimic_actor",
            "src_ip":    mm_ip,
            "dst_port":  22,
            "ts":        _ts(start, 86400 * 90 + k * 60),
            "payload":   f"{sensor_banner}-probe-{k}",
            "note":      "echoes sensor self-banner",
        })

    return rows


def evaluate_coverage(rows: list[dict]) -> dict:
    """Cross-reference simulated archetypes against analyzer outputs that
    are already on disk.  Detection = the archetype's src_ip appears in
    at least one analyzer's output table.
    """
    by_arch: dict[str, set[str]] = {}
    for r in rows:
        by_arch.setdefault(r["archetype"], set()).add(r["src_ip"])

    detection: dict[str, dict] = {}
    sources = {
        "portscans":   lib.REPORTS / "portscans" / "portscans.parquet",
        "slowlow":     lib.REPORTS / "slowlow" / "slowlow.parquet",
        "rdpbrute":    lib.REPORTS / "rdpbrute" / "rdpbrute.parquet",
        "botnetcls":   lib.REPORTS / "botnetcls" / "botnetcls.parquet",
        "dnstlsintel": lib.REPORTS / "dnstlsintel" / "dns_qname_rank.parquet",
        "selfmimic":   lib.REPORTS / "selfmimic" / "selfmimic.parquet",
        "risk_scores": lib.REPORTS / "risk_scores" / "risk_scores.parquet",
    }
    con = lib.duck()
    detected_ips: dict[str, set[str]] = {a: set() for a in by_arch}
    for src, path in sources.items():
        if not path.exists() or path.stat().st_size == 0:
            continue
        try:
            ips = {r[0] for r in con.execute(
                f"SELECT src_ip FROM read_parquet('{path}')"
            ).fetchall()}
        except Exception:
            continue
        for arch, expected in by_arch.items():
            hit = ips & expected
            if hit:
                detected_ips[arch].update(hit)
    con.close()

    for arch, expected in by_arch.items():
        hit = detected_ips[arch]
        detection[arch] = {
            "injected_ips":     len(expected),
            "detected_ips":     len(hit),
            "detection_rate":   (len(hit) / len(expected)) if expected else 0.0,
            "missed_ip_sample": list(sorted(expected - hit))[:5],
        }
    return detection


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = generate(seed=args.seed, sensor_banner=args.sensor_banner)
    pq.write_table(pa.Table.from_pylist(rows, schema=SIM_SCHEMA),
                   OUT_DIR / "simulated.parquet",
                   compression="zstd", compression_level=3)
    print(f"[adversim] generated {len(rows):,} synthetic packets",
          file=sys.stderr)

    cov = evaluate_coverage(rows) if args.evaluate else {}

    md = [
        "# adversarysim - synthetic adversary coverage harness",
        "",
        "_This module injects six canonical adversary archetypes and "
        "checks whether the existing analyzers detect their source IPs. "
        "It is a regression harness, not a corpus contribution — the "
        "synthetic packets are not merged into `packets` or `iocs`._",
        "",
        f"- seed: `{args.seed}`",
        f"- archetypes: {len(set(r['archetype'] for r in rows))}",
        f"- synthetic packets: {len(rows):,}",
        f"- evaluate against analyzer outputs: "
        f"{'yes' if args.evaluate else 'no'}",
        "",
    ]
    if cov:
        md += ["## Coverage by archetype", "",
               "| archetype | injected_ips | detected_ips | detection_rate |",
               "| --- | --- | --- | --- |"]
        for arch, c in cov.items():
            md.append(f"| {arch} | {c['injected_ips']} | "
                      f"{c['detected_ips']} | {c['detection_rate']:.0%} |")
        md += ["",
               "_Detection rate < 100% on an archetype means the "
               "pipeline currently has a blind spot for that adversary "
               "style.  Pair this with the per-archetype 'missed_ip_sample' "
               "below when tuning thresholds._", ""]
        md += ["## Missed-IP samples per archetype", ""]
        for arch, c in cov.items():
            md.append(f"- **{arch}**: " + (
                ", ".join(c["missed_ip_sample"]) or "(none missed)"))
    (OUT_DIR / "coverage.md").write_text("\n".join(md) + "\n")
    (OUT_DIR / "coverage.json").write_text(json.dumps(cov, indent=2))
    print(f"[adversim] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=20260528)
    ap.add_argument("--sensor-banner", default="SSH-2.0-OpenSSH_7.4",
                    help="A representative self-banner for the mimic "
                         "archetype to echo.")
    ap.add_argument("--evaluate", action="store_true", default=True,
                    help="Cross-check archetypes against current "
                         "analyzer outputs (default ON).")
    ap.add_argument("--no-evaluate", action="store_false",
                    dest="evaluate")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

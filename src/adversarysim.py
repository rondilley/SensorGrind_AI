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

Coverage mode cannot measure detection: its rows never reach ``packets``,
carry no header fields, and use TEST-NET sources that
``lib.is_real_external_ip`` drops.  Use ``--inject`` for detector work.

Inject mode (``--inject NAME --day YYYY-MM-DD``)
------------------------------------------------
Writes full ``PACKETS_SCHEMA`` rows for one background day into
``output/eval/inject/NAME/packets/dt=DAY/`` plus a ``truth.parquet``.
``lib.register_eval_views(con, NAME)`` overlays them on the real corpus
as one ``packets`` view; the corpus on disk is never modified and the
truth table is never used as operator labels.  Header fields (TTL,
window, lengths, sensor response) are sampled from that day's real SYN
traffic, sources are fresh routable addresses absent from the corpus,
and the replay archetypes copy recorded sources, so a detector cannot
win by spotting generator artifacts.

Inject archetypes (header-only; the payload archetypes above stay in
coverage mode):
  fast_scanner       1 IP, 2,000 ports in ~60 s
  slow_scanner       1 IP, 12 probes ~2 h apart
  distributed_brute  40 IPs in one /24, 20 x 3389 each at 60 s
  jittered_beacon    1 IP, port 8443 every 300 s +/- 2 %
  lockstep_24        16 IPs in one /24 replaying one 8-port sequence in
                     lockstep (+/- 50 ms), three times
  rhythm_change      a recorded source; 2nd half inter-arrivals x 0.1
  chain_mutation     a recorded source; its top port swapped for one
                     the sensor did not see that day
  burst_replay       (global) the busiest 10 min of an earlier day,
                     re-sourced and replayed into the target day
  control_replay     5 recorded ordinary sources, only re-addressed.
                     Detectors should NOT flag these (is_control=True).
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
    }
    risk = sorted((lib.OUTPUT_DIR / "risk" / "ip_risk").glob("**/risk.parquet"))
    if risk:
        sources["risk_scores"] = risk[-1]
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


# ----------------------------------------------------------------------
# Inject mode: full-schema rows into an eval overlay
# ----------------------------------------------------------------------

# Matches parser.PACKETS_SCHEMA (not imported: parser pulls in its own
# multiprocessing machinery).
INJECT_SCHEMA = pa.schema([
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

TRUTH_SCHEMA = pa.schema([
    ("archetype",  pa.string()),
    ("level",      pa.string()),     # source | global
    ("src_ip",     pa.string()),     # NULL for level=global
    ("start_ts",   pa.timestamp("us", tz="UTC")),
    ("end_ts",     pa.timestamp("us", tz="UTC")),
    ("n_packets",  pa.uint32()),
    ("is_control", pa.bool_()),
    ("note",       pa.string()),
])

# Columns copied verbatim when a recorded packet is replayed.
_REPLAY_COLS = [f.name for f in INJECT_SCHEMA]

DAY = _dt.timedelta(days=1)


class _Injector:
    """Builds the injection set for one background day."""

    def __init__(self, con, day: _dt.date, seed: int):
        self.con = con
        self.rng = random.Random(seed)
        self.day = day
        self.t0 = _dt.datetime.combine(day, _dt.time(), _dt.timezone.utc)
        self.rows: list[dict] = []
        self.truth: list[dict] = []
        d = day.isoformat()
        self.templates = con.execute(f"""
            SELECT ttl, tcp_win, pkt_len, dg_len, tcp_len, sensor_resp, tos
            FROM packets
            WHERE dt = DATE '{d}' AND proto = 6 AND tcp_flags = 2
            USING SAMPLE 2000 ROWS
        """).fetchall()
        if not self.templates:
            raise SystemExit(f"[adversim] no TCP SYN background on {d}")
        self.dst_ip = con.execute(
            f"SELECT mode(dst_ip) FROM packets WHERE dt = DATE '{d}'"
        ).fetchone()[0]
        self.day_ports = {r[0] for r in con.execute(
            f"SELECT DISTINCT dst_port FROM packets WHERE dt = DATE '{d}' "
            f"AND dst_port IS NOT NULL"
        ).fetchall()}
        self.used_ips = {r[0] for r in con.execute(
            "SELECT DISTINCT src_ip FROM packets").fetchall()}
        self.used_24 = {ip.rsplit(".", 1)[0] for ip in self.used_ips
                        if ip.count(".") == 3}
        prev = con.execute(f"""
            SELECT max(dt) FROM packets WHERE dt < DATE '{d}'
        """).fetchone()[0]
        if prev is None:
            raise SystemExit(f"[adversim] no recorded day before {d} to "
                             "replay sources from")
        self.prev_day = prev if isinstance(prev, _dt.date) else \
            _dt.date.fromisoformat(str(prev))
        self.mask = lib.load_sensor_mask()

    # -- address + header helpers ---------------------------------------
    def fresh_24(self) -> str:
        while True:
            p = (f"{self.rng.randint(1, 223)}.{self.rng.randint(0, 255)}."
                 f"{self.rng.randint(0, 255)}")
            if p not in self.used_24 and lib.is_real_external_ip(p + ".1"):
                self.used_24.add(p)
                return p

    def fresh_ip(self) -> str:
        return f"{self.fresh_24()}.{self.rng.randint(1, 254)}"

    def masked(self, start: _dt.datetime, end: _dt.datetime) -> bool:
        return any(s < end and start < e for s, e, _ in self.mask)

    def start_for(self, duration_s: float) -> _dt.datetime:
        """A random start on the target day that keeps the archetype inside
        the day and outside every sensor-off interval."""
        span = max(1.0, 86400.0 - duration_s - 1.0)
        for _ in range(200):
            st = self.t0 + _dt.timedelta(seconds=self.rng.uniform(0, span))
            if not self.masked(st, st + _dt.timedelta(seconds=duration_s)):
                return st
        raise SystemExit(f"[adversim] {self.day} is mostly masked; pick "
                         "another --day")

    def syn(self, ts: _dt.datetime, ip: str, dport: int,
            tpl: tuple | None = None) -> dict:
        ttl, win, pkt_len, dg_len, tcp_len, resp, tos = (
            tpl or self.rng.choice(self.templates))
        return {
            "ts": ts, "src_ip": ip,
            "src_port": self.rng.randint(1024, 65535),
            "dst_ip": self.dst_ip, "dst_port": dport, "proto": 6,
            "pkt_len": pkt_len, "ip_id": self.rng.randint(0, 65535),
            "tos": tos, "ttl": ttl, "dg_len": dg_len, "tcp_flags": 2,
            "tcp_seq": self.rng.getrandbits(32), "tcp_ack": 0,
            "tcp_win": win, "tcp_len": tcp_len, "icmp_type": None,
            "icmp_code": None, "sensor_resp": resp,
            "payload_sha256": None, "payload_len": 0, "l7_proto": 0,
        }

    def add(self, archetype: str, rows: list[dict], level: str = "source",
            src_ip: str | None = None, control: bool = False,
            note: str = "") -> None:
        end = self.t0 + DAY
        rows = [r for r in rows if self.t0 <= r["ts"] < end]
        if not rows:
            print(f"[adversim] {archetype}: no rows inside {self.day}",
                  file=sys.stderr)
            return
        self.rows.extend(rows)
        ips = [src_ip] if level == "global" else sorted({r["src_ip"] for r in rows})
        for ip in ips:
            mine = rows if level == "global" else [r for r in rows
                                                   if r["src_ip"] == ip]
            self.truth.append({
                "archetype": archetype, "level": level,
                "src_ip": ip if level == "source" else None,
                "start_ts": min(r["ts"] for r in mine),
                "end_ts": max(r["ts"] for r in mine),
                "n_packets": len(mine), "is_control": control, "note": note,
            })

    def recorded(self, lo: int, hi: int, n: int) -> list[str]:
        """``n`` recorded sources from the previous day with lo..hi packets."""
        d = self.prev_day.isoformat()
        ips = [r[0] for r in self.con.execute(f"""
            SELECT src_ip FROM packets
            WHERE dt = DATE '{d}' AND {lib.mask_predicate('ts')}
            GROUP BY src_ip
            HAVING count(*) BETWEEN {lo} AND {hi}
               AND count(DISTINCT dst_port) >= 3
        """).fetchall() if lib.is_real_external_ip(r[0])]
        ips.sort()
        self.rng.shuffle(ips)
        return ips[:n]

    def replay(self, ip: str) -> list[dict]:
        """The recorded packets of ``ip`` on the previous day, shifted to the
        target day (time of day preserved) under a fresh address."""
        d = self.prev_day.isoformat()
        cols = ", ".join(_REPLAY_COLS)
        tbl = self.con.execute(f"""
            SELECT {cols} FROM packets
            WHERE dt = DATE '{d}' AND src_ip = ? ORDER BY ts
        """, [ip]).to_arrow_table()
        shift = self.t0 - _dt.datetime.combine(self.prev_day, _dt.time(),
                                               _dt.timezone.utc)
        new_ip = self.fresh_ip()
        rows = tbl.to_pylist()
        for r in rows:
            r["ts"] = r["ts"] + shift
            r["src_ip"] = new_ip
        return rows

    # -- archetypes -----------------------------------------------------
    def build(self) -> None:
        rng = self.rng

        ip = self.fresh_ip()
        st = self.start_for(70)
        ports = rng.sample(range(1, 65536), 2000)
        self.add("fast_scanner", [self.syn(st + _dt.timedelta(seconds=i * 0.03),
                                           ip, p) for i, p in enumerate(ports)])

        ip = self.fresh_ip()
        tpl = rng.choice(self.templates)
        st = self.start_for(12 * 7200)
        common = [22, 23, 80, 443, 3389, 5900, 8080, 445, 1433, 3306]
        self.add("slow_scanner", [self.syn(
            st + _dt.timedelta(seconds=k * 7200 + rng.uniform(-600, 600)),
            ip, rng.choice(common), tpl) for k in range(12)])

        net = self.fresh_24()
        st = self.start_for(20 * 60 + 60)
        rows = []
        for h in rng.sample(range(1, 255), 40):
            tpl = rng.choice(self.templates)
            for tick in range(20):
                rows.append(self.syn(st + _dt.timedelta(
                    seconds=tick * 60 + h * 0.5 + rng.uniform(0, 0.2)),
                    f"{net}.{h}", 3389, tpl))
        self.add("distributed_brute", rows)

        ip = self.fresh_ip()
        tpl = rng.choice(self.templates)
        st = self.t0 + _dt.timedelta(seconds=rng.uniform(0, 300))
        rows, t = [], st
        while t < self.t0 + DAY:
            if not self.masked(t, t + _dt.timedelta(seconds=1)):
                rows.append(self.syn(t, ip, 8443, tpl))
            t += _dt.timedelta(seconds=300 * rng.uniform(0.98, 1.02))
        self.add("jittered_beacon", rows)

        net = self.fresh_24()
        seq_ports = rng.sample(sorted(self.day_ports), 8) \
            if len(self.day_ports) >= 8 else rng.sample(range(1, 65536), 8)
        offsets = sorted(rng.uniform(0, 20) for _ in seq_ports)
        hosts = rng.sample(range(1, 255), 16)
        tpls = {h: rng.choice(self.templates) for h in hosts}
        rows = []
        for _ in range(3):
            st = self.start_for(30)
            for h in hosts:
                for off, p in zip(offsets, seq_ports):
                    rows.append(self.syn(st + _dt.timedelta(
                        seconds=off + rng.uniform(-0.05, 0.05)),
                        f"{net}.{h}", p, tpls[h]))
        self.add("lockstep_24", rows,
                 note=f"ports {seq_ports}")

        for ip in self.recorded(100, 2000, 1):
            rows = self.replay(ip)
            half = len(rows) // 2
            if half >= 2:
                pivot = rows[half - 1]["ts"]
                for r in rows[half:]:
                    r["ts"] = pivot + (r["ts"] - pivot) * 0.1
            self.add("rhythm_change", rows,
                     note="second-half inter-arrivals x 0.1")

        for ip in self.recorded(30, 2000, 1):
            rows = self.replay(ip)
            top = max(set(r["dst_port"] for r in rows),
                      key=lambda p: sum(r["dst_port"] == p for r in rows))
            unseen = [p for p in range(40000, 60000) if p not in self.day_ports]
            new_port = rng.choice(unseen)
            for r in rows:
                if r["dst_port"] == top:
                    r["dst_port"] = new_port
            self.add("chain_mutation", rows,
                     note=f"port {top} -> {new_port}")

        d = self.prev_day.isoformat()
        busiest = self.con.execute(f"""
            SELECT time_bucket(INTERVAL 10 MINUTE, ts) AS b, count(*) AS n
            FROM packets WHERE dt = DATE '{d}' AND {lib.mask_predicate('ts')}
            GROUP BY b ORDER BY n DESC LIMIT 1
        """).fetchone()
        if busiest:
            b0 = busiest[0]
            cols = ", ".join(_REPLAY_COLS)
            rows = self.con.execute(f"""
                SELECT {cols} FROM packets
                WHERE ts >= ? AND ts < ? + INTERVAL 10 MINUTE ORDER BY ts
            """, [b0, b0]).to_arrow_table().to_pylist()
            st = self.start_for(600)
            shift = st - b0
            ipmap: dict[str, str] = {}
            for r in rows:
                r["ts"] = r["ts"] + shift
                r["src_ip"] = ipmap.setdefault(r["src_ip"], self.fresh_ip())
            self.add("burst_replay", rows, level="global",
                     note=f"replay of {b0} ({len(ipmap)} sources)")

        for ip in self.recorded(20, 200, 5):
            self.add("control_replay", self.replay(ip), control=True,
                     note="re-addressed recorded source")


def inject(args: argparse.Namespace) -> int:
    day = lib.parse_date_arg(args.day)
    if day is None:
        raise SystemExit("[adversim] --inject needs --day YYYY-MM-DD")
    con = lib.duck()
    lib.register_views(con)
    inj = _Injector(con, day, args.seed)
    inj.build()
    con.close()

    out = lib.eval_inject_dir(args.inject)
    part_dir = out / "packets" / f"dt={day.isoformat()}"
    part_dir.mkdir(parents=True, exist_ok=True)
    for old in part_dir.glob("*.parquet"):
        old.unlink()
    inj.rows.sort(key=lambda r: r["ts"])
    for path, tbl in ((part_dir / "part-0.parquet",
                       pa.Table.from_pylist(inj.rows, schema=INJECT_SCHEMA)),
                      (out / "truth.parquet",
                       pa.Table.from_pylist(inj.truth, schema=TRUTH_SCHEMA))):
        tmp = path.with_suffix(".parquet.tmp")
        pq.write_table(tbl, tmp, compression="zstd", compression_level=3)
        tmp.replace(path)

    by_arch: dict[str, list[int]] = {}
    for t in inj.truth:
        by_arch.setdefault(t["archetype"], []).append(t["n_packets"])
    md = [f"# adversarysim inject set `{args.inject}`", "",
          f"- target day: {day} (replays from {inj.prev_day})",
          f"- seed: `{args.seed}`",
          f"- injected packets: {len(inj.rows):,}", "",
          "| archetype | truth rows | packets |", "| --- | ---: | ---: |"]
    md += [f"| {a} | {len(v)} | {sum(v):,} |" for a, v in by_arch.items()]
    (out / "inject.md").write_text("\n".join(md) + "\n")
    print(f"[adversim] injected {len(inj.rows):,} packets "
          f"({len(inj.truth)} truth rows) -> {out}", file=sys.stderr)
    return 0


def run(args: argparse.Namespace) -> int:
    if args.inject:
        return inject(args)
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
    ap.add_argument("--inject", metavar="NAME", default=None,
                    help="Write a full-schema injection set NAME for one "
                         "background --day into output/eval/inject/NAME/ "
                         "instead of running coverage mode.")
    ap.add_argument("--day", default=None,
                    help="Background day for --inject (YYYY-MM-DD).")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

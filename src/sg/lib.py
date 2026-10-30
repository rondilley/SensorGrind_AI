"""
sg.lib — shared helpers for SensorGrind_AI analyzer modules.

Provides:
    - paths to the Parquet store, GeoLite mmdbs, and report outputs
    - DuckDB connection factory (configured for our data layout)
    - GeoIP / ASN / Country lookup with auto-discovery of the newest db
    - Output writer that emits a Parquet result and a Markdown summary together
    - Enum dictionaries that match parser.py constants (L7, IOC, RESP, FLAGS)
    - A "self-IP" allowlist for filtering the sensor's own public IPs from IOCs
    - Time-window helpers
"""

from __future__ import annotations

import atexit
import datetime as _dt
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq


# ----------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------

REPO_ROOT  = Path(__file__).resolve().parents[2]

# Source data only - raw inputs (merged.log.gz, etc.) live here.
DATA_DIR   = REPO_ROOT / "data"

# Everything produced by the tool - parser parquet tables, analyzer
# reports, feature snapshots, models, mined patterns, risk scores,
# dossiers - goes under output/.  Env vars override for staging runs.
OUTPUT_DIR = Path(os.environ.get("SG_OUTPUT", REPO_ROOT / "output"))
PARQUET    = Path(os.environ.get("SG_PARQUET", OUTPUT_DIR / "parquet"))
REPORTS    = Path(os.environ.get("SG_REPORTS", OUTPUT_DIR / "reports"))
GEOLITE    = REPO_ROOT / "GeoLite"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORTS.mkdir(parents=True, exist_ok=True)

# Path globs the analyzers will use to read the parser's output.
PACKETS_GLOB       = str(PARQUET / "packets" / "**" / "*.parquet")
BLOBS_GLOB         = str(PARQUET / "payload_blobs" / "**" / "*.parquet")
L7_GLOB            = str(PARQUET / "l7_events" / "**" / "*.parquet")
IOCS_GLOB          = str(PARQUET / "iocs" / "**" / "*.parquet")

# Derived, ASN/CIDR/IP-clustered packets (built by src/cluster_packets.py):
# bucketed by hash(asn), sorted by (asn, cidr, src_ip), with asn+cidr columns.
# Lets per-IP / per-ASN / per-CIDR analyzers read a bounded, prunable window.
PACKETS_CLUSTERED      = PARQUET / "packets_clustered"
PACKETS_CLUSTERED_GLOB = str(PACKETS_CLUSTERED / "**" / "*.parquet")
L7_CLUSTERED           = PARQUET / "l7_events_clustered"
L7_CLUSTERED_GLOB      = str(L7_CLUSTERED / "**" / "*.parquet")
IOCS_CLUSTERED         = PARQUET / "iocs_clustered"
IOCS_CLUSTERED_GLOB    = str(IOCS_CLUSTERED / "**" / "*.parquet")


def has_clustered(d: Path) -> bool:
    """True if a clustered dataset dir has been built (has bkt= partitions)."""
    return d.exists() and any(d.glob("bkt=*"))


def clustered_buckets() -> list[int]:
    """Bucket numbers present in the clustered packets dataset (empty if it
    hasn't been built yet).  All clustered tables share these bucket numbers."""
    if not PACKETS_CLUSTERED.exists():
        return []
    out = []
    for d in PACKETS_CLUSTERED.glob("bkt=*"):
        try:
            out.append(int(d.name.split("=", 1)[1]))
        except (IndexError, ValueError):
            continue
    return sorted(out)


# ----------------------------------------------------------------------
# Enum decoders (match parser.py constants)
# ----------------------------------------------------------------------

PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}

RESP_NAME = {0: "", 1: "SA", 2: "FA", 3: "A", 4: "R", 5: "ICMP"}

L7_NAME = {
    0: "unknown", 1: "http", 2: "tls", 3: "ssh", 4: "ftp", 5: "smtp",
    6: "dns", 7: "telnet", 8: "rdp", 9: "smb", 10: "mqtt", 11: "irc",
    12: "bittorrent", 13: "mirai", 14: "mongo", 15: "redis", 16: "vnc",
    17: "levin",
}
L7_ID = {v: k for k, v in L7_NAME.items()}

IOC_NAME = {
    0: "url", 1: "domain", 2: "ipv4", 3: "ipv6", 4: "file_hash", 5: "cmd",
    6: "cred", 7: "mstshash", 8: "user_agent", 9: "ssh_banner",
    10: "tls_sni", 11: "http_host", 12: "http_uri", 13: "dns_query",
}
IOC_ID = {v: k for k, v in IOC_NAME.items()}

# TCP flag bits (matches parser.py)
FLAG_URG, FLAG_ACK, FLAG_PSH, FLAG_RST, FLAG_SYN, FLAG_FIN = (
    1 << 5, 1 << 4, 1 << 3, 1 << 2, 1 << 1, 1 << 0,
)


def flags_to_letters(mask: int | None) -> str:
    if mask is None:
        return ""
    out = []
    if mask & FLAG_URG: out.append("U")
    if mask & FLAG_ACK: out.append("A")
    if mask & FLAG_PSH: out.append("P")
    if mask & FLAG_RST: out.append("R")
    if mask & FLAG_SYN: out.append("S")
    if mask & FLAG_FIN: out.append("F")
    return "".join(out)


# ----------------------------------------------------------------------
# DuckDB connection
# ----------------------------------------------------------------------

def auto_memory_limit(fraction: float = 0.4, min_gb: int = 4) -> str:
    """A DuckDB ``memory_limit`` sized to THIS host: ``fraction`` of physical
    RAM, floored at ``min_gb``.

    Heavy stages that run serialized (chainfp, compositeprint) were pinned to a
    hardcoded 8GB, which OOM'd on a 1.1B-packet corpus even though the box had
    62GB free.  Sizing to the host lets them use the machine they're on, while
    the fraction (not the whole box) and the floor keep it safe on small
    systems and leave headroom for DuckDB's PARTITION_BY write buffers (which
    are not bounded by memory_limit) plus the OS.
    """
    try:
        total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        gb = max(min_gb, int(total / (1024 ** 3) * fraction))
    except (ValueError, OSError, AttributeError):
        gb = min_gb
    return f"{gb}GB"


def duck(read_only: bool = False, memory_limit: str | None = None,
         threads: int | None = None) -> duckdb.DuckDBPyConnection:
    """Return a DuckDB connection tuned for the SensorGrind workload.

    Uses an in-memory database (DuckDB still reads Parquet directly from disk).

    Parameters
    ----------
    read_only
        Currently advisory: DuckDB's in-memory connection does not support
        the SQLite-style ``read_only=True`` flag, and most analyzers need
        ``CREATE TEMP TABLE`` for staging.  Kept in the signature so callers
        can declare intent; if you need a hard guarantee, point your
        analyzer at a file-backed ``.duckdb`` and pass ``read_only=True``
        to ``duckdb.connect`` directly.  Default is ``False`` so the
        parameter no longer lies about what it does.
    memory_limit
        Override via the ``SG_DUCK_MEM`` env var (default ``'12GB'``).
    threads
        Default is ``CPU count // 2``.
    """
    if memory_limit is None:
        memory_limit = os.environ.get("SG_DUCK_MEM", "12GB")
    con = duckdb.connect(":memory:", read_only=False)
    con.execute(f"SET memory_limit='{memory_limit}'")
    if threads is None:
        threads = max(2, (os.cpu_count() or 4) // 2)
    con.execute(f"SET threads={threads}")
    con.execute("SET preserve_insertion_order=false")
    con.execute("SET enable_progress_bar=false")
    # Enable out-of-core operation.  Without a temp_directory an in-memory
    # DuckDB cannot spill hash aggregates / joins to disk, so a large
    # GROUP BY blows past memory_limit and gets OOM-killed instead of
    # spilling.
    #
    # CRITICAL: every connection gets its OWN spill dir.  Concurrent DuckDB
    # instances (parallel evolve stages) that share one temp_directory collide
    # on identically-named temp files and corrupt each other's spill
    # ("Could not read enough bytes from ... duckdb_temp_storage").  Base dir
    # via SG_DUCK_TMPDIR; per-connection subdir is unique.
    base = os.environ.get("SG_DUCK_TMPDIR") or str(OUTPUT_DIR / ".duckdb_tmp")
    try:
        Path(base).mkdir(parents=True, exist_ok=True)
        _prune_stale_tmp(base)
        tmp = tempfile.mkdtemp(prefix=f"con{os.getpid()}_", dir=base)
        con.execute(f"SET temp_directory='{tmp}'")
        atexit.register(shutil.rmtree, tmp, True)  # ignore_errors=True
    except OSError:
        pass
    return con


def _pid_alive(pid: int) -> bool:
    """True if a process with ``pid`` currently exists.  Errs toward 'alive'
    so we never delete a spill dir that might still be in use."""
    if pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True            # exists but not signalable (e.g. perms)
    return True


def _prune_stale_tmp(base: str) -> None:
    """Remove per-connection spill dirs whose owning process is GONE.  Keyed on
    the pid embedded in the dir name (``con<pid>_<rand>``), so a live
    connection's dir -- this one or a concurrent stage's -- is never deleted,
    no matter how long it has been running."""
    try:
        for d in Path(base).glob("con*_*"):
            if not d.is_dir():
                continue
            try:
                pid = int(d.name[3:d.name.index("_", 3)])
            except ValueError:
                continue
            if not _pid_alive(pid):
                shutil.rmtree(d, ignore_errors=True)
    except OSError:
        pass


def register_views(con: duckdb.DuckDBPyConnection,
                   clustered: bool = False) -> None:
    """Register the four canonical views every analyzer expects.

    With ``clustered=True``, point the ``packets`` view at the ASN/CIDR/IP
    clustered dataset when it has been built (it carries the same rows plus
    ``asn``/``cidr`` columns, sorted for row-group pruning).  Falls back to
    the raw date-partitioned packets otherwise, so callers are safe either
    way.  Best for per-IP / per-ASN / per-CIDR scans.
    """
    pkts = PACKETS_CLUSTERED_GLOB if (clustered and has_clustered(PACKETS_CLUSTERED)) else PACKETS_GLOB
    l7   = L7_CLUSTERED_GLOB      if (clustered and has_clustered(L7_CLUSTERED))      else L7_GLOB
    iocs = IOCS_CLUSTERED_GLOB    if (clustered and has_clustered(IOCS_CLUSTERED))    else IOCS_GLOB
    con.execute(f"CREATE OR REPLACE VIEW packets       AS SELECT * FROM read_parquet('{pkts}', hive_partitioning=1)")
    con.execute(f"CREATE OR REPLACE VIEW payload_blobs AS SELECT * FROM read_parquet('{BLOBS_GLOB}', hive_partitioning=1)")
    con.execute(f"CREATE OR REPLACE VIEW l7_events     AS SELECT * FROM read_parquet('{l7}',   hive_partitioning=1)")
    con.execute(f"CREATE OR REPLACE VIEW iocs          AS SELECT * FROM read_parquet('{iocs}', hive_partitioning=1)")


def load_report(con: duckdb.DuckDBPyConnection, path: Path, sql: str) -> list:
    """Run ``sql`` against a parquet at ``path`` and return the rows.

    Returns ``[]`` if ``path`` doesn't exist - no analyzer's failure
    propagates a missing input.  ``sql`` should reference the parquet
    via the literal ``{path}`` placeholder; the helper substitutes a
    safe ``read_parquet('...')`` expression in its place so call sites
    don't need to repeat the if-exists / open / fetchall boilerplate.

    Example:
        rows = lib.load_report(
            con, REPORTS / "workhours" / "workhours.parquet",
            "SELECT dow, hour_utc, pkt_count FROM {path}",
        )
    """
    if not path.exists():
        return []
    return con.execute(sql.format(path=f"read_parquet('{path}')")).fetchall()


# ----------------------------------------------------------------------
# GeoIP / ASN lookup with auto-discovery
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class GeoRecord:
    ip: str
    country: str | None
    country_iso: str | None
    city: str | None
    region: str | None
    lat: float | None
    lon: float | None
    asn: int | None
    asn_org: str | None


def _newest_subdir(parent: Path, prefix: str) -> Path | None:
    # Directories only — skip the matching .tar.gz archives MaxMind ships alongside.
    candidates = sorted(p for p in parent.glob(f"{prefix}*") if p.is_dir())
    return candidates[-1] if candidates else None


def find_geolite_paths() -> dict[str, Path]:
    """Auto-pick the newest GeoLite db of each kind."""
    out: dict[str, Path] = {}
    for kind, prefix, fname in (
        ("city",    "GeoLite2-City_",    "GeoLite2-City.mmdb"),
        ("asn",     "GeoLite2-ASN_",     "GeoLite2-ASN.mmdb"),
        ("country", "GeoLite2-Country_", "GeoLite2-Country.mmdb"),
    ):
        d = _newest_subdir(GEOLITE, prefix)
        if d is not None:
            mmdb = d / fname
            if mmdb.exists():
                out[kind] = mmdb
    return out


class GeoLookup:
    """Wraps the City + ASN mmdbs. Caches results in-process."""

    def __init__(self, paths: dict[str, Path] | None = None):
        import geoip2.database  # local import keeps lib lazy
        self._paths = paths or find_geolite_paths()
        self._city = geoip2.database.Reader(str(self._paths["city"])) if "city" in self._paths else None
        self._asn  = geoip2.database.Reader(str(self._paths["asn"]))  if "asn"  in self._paths else None
        self._cache: dict[str, GeoRecord] = {}

    def lookup(self, ip: str) -> GeoRecord:
        rec = self._cache.get(ip)
        if rec is not None:
            return rec
        country = country_iso = city = region = asn_org = None
        lat = lon = None
        asn = None
        try:
            if self._city is not None:
                r = self._city.city(ip)
                country     = r.country.name
                country_iso = r.country.iso_code
                city        = r.city.name
                region      = r.subdivisions.most_specific.name if r.subdivisions else None
                lat         = r.location.latitude
                lon         = r.location.longitude
        except Exception:
            pass
        try:
            if self._asn is not None:
                a = self._asn.asn(ip)
                asn     = a.autonomous_system_number
                asn_org = a.autonomous_system_organization
        except Exception:
            pass
        rec = GeoRecord(ip, country, country_iso, city, region, lat, lon, asn, asn_org)
        self._cache[ip] = rec
        return rec

    def close(self) -> None:
        for r in (self._city, self._asn):
            try:
                if r is not None:
                    r.close()
            except Exception:
                pass


# ----------------------------------------------------------------------
# Self-IP filter (avoid tagging the sensor's own public IPs as IOCs)
# ----------------------------------------------------------------------

# IPs the sensor is reachable as, that scanners may echo in their probes.
# Update as needed. Read from $SG_SELF_IPS (comma-separated) if set.
DEFAULT_SELF_IPS: tuple[str, ...] = (
    "10.10.10.40",   # internal honeypot
    "99.88.84.21",   # observed in FortiWiFi NAT logs
    "99.88.84.61",   # observed in FortiWiFi NAT logs
)

def self_ips() -> set[str]:
    extra = os.environ.get("SG_SELF_IPS", "")
    base = set(DEFAULT_SELF_IPS)
    base.update(s.strip() for s in extra.split(",") if s.strip())
    return base


import ipaddress as _ipaddr

# Networks we never want as IOCs.  Built with the stdlib ``ipaddress``
# module so the membership check handles supernet relationships, IPv6,
# and CGNAT (RFC 6598 100.64.0.0/10) automatically - replacing the
# previous hand-rolled string-prefix scan that was IPv4-only, missed
# CGNAT, and incorrectly classified e.g. ``1.1.1.10`` as bogon because
# of the ``"1."`` prefix match.
_BOGON_NETS: tuple = tuple(_ipaddr.ip_network(n) for n in (
    # IPv4
    "0.0.0.0/8",            # current network, RFC 1122
    "10.0.0.0/8",           # private RFC 1918
    "100.64.0.0/10",        # CGNAT RFC 6598
    "127.0.0.0/8",          # loopback
    "169.254.0.0/16",       # link-local
    "172.16.0.0/12",        # private RFC 1918
    "192.0.0.0/24",         # IETF
    "192.0.2.0/24",         # RFC 5737 TEST-NET-1
    "192.88.99.0/24",       # legacy 6to4 anycast (RFC 7526 deprecated)
    "192.168.0.0/16",       # private RFC 1918
    "198.18.0.0/15",        # RFC 2544 benchmarking
    "198.51.100.0/24",      # RFC 5737 TEST-NET-2
    "203.0.113.0/24",       # RFC 5737 TEST-NET-3
    "224.0.0.0/4",           # multicast
    "240.0.0.0/4",           # reserved + 255.255.255.255 broadcast
    # IPv6
    "::/128",                # unspecified
    "::1/128",               # loopback
    "fc00::/7",              # unique local addresses
    "fe80::/10",             # link-local
    "ff00::/8",              # multicast
    "2001:db8::/32",         # documentation
))

# Specific addresses we don't want as IOCs (rare-real, common-DNS).
_BOGON_LITERALS: frozenset = frozenset((
    "1.1.1.1", "1.0.0.1",    # Cloudflare DNS
    "8.8.8.8", "8.8.4.4",    # Google DNS
    "9.9.9.9", "149.112.112.112",  # Quad9
))


def is_real_external_ip(ip: str) -> bool:
    """Return True if ``ip`` is a routable, non-self, non-documentation address.

    Handles IPv4 and IPv6.  Uses ``ipaddress`` proper subnet containment
    instead of string-prefix matching, so it correctly distinguishes
    e.g. ``1.1.1.1`` (bogon literal) from ``1.1.1.10`` (real public IP).
    """
    if not ip:
        return False
    if ip in self_ips() or ip in _BOGON_LITERALS:
        return False
    try:
        addr = _ipaddr.ip_address(ip)
    except ValueError:
        return False
    for net in _BOGON_NETS:
        if isinstance(addr, type(net.network_address)) and addr in net:
            return False
    return True


# Backwards-compatibility shim: a handful of analyzer modules still
# import BOGON_PREFIXES.  Keep the symbol with the same semantics as
# before so we don't break them on first read, but flag that the
# canonical containment test is now ``is_real_external_ip``.
BOGON_PREFIXES: tuple[str, ...] = tuple(
    f"{int(o):d}." for o in range(256) for net in _BOGON_NETS
    if isinstance(net, _ipaddr.IPv4Network) and net.prefixlen <= 8 and
    int(net.network_address) >> 24 == o
)[:0]  # intentionally empty - new code should use is_real_external_ip


# ----------------------------------------------------------------------
# Output writer — Parquet result + Markdown summary side-by-side
# ----------------------------------------------------------------------

@dataclass
class Report:
    """One analyzer's output. ``rows`` becomes the Parquet result;
    ``markdown`` is rendered into a human-readable .md alongside it."""
    name: str
    rows: list[dict] | "pa.Table" = None  # type: ignore[assignment]
    schema: pa.Schema | None = None
    markdown: str = ""

    def write(self, suffix: str | None = None) -> dict[str, Path]:
        ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"{self.name}_{suffix}" if suffix else self.name
        out_dir = REPORTS / self.name
        out_dir.mkdir(parents=True, exist_ok=True)
        parquet_path = out_dir / f"{stem}.parquet"
        md_path      = out_dir / f"{stem}.md"

        # Always write a valid Parquet file - even when there are no rows -
        # so downstream read_parquet() globs and DuckDB views don't blow up
        # on a zero-byte placeholder (a real bug spotted by the multi-AI
        # methodology review).
        if isinstance(self.rows, pa.Table):
            table = self.rows
        elif self.rows:
            table = pa.Table.from_pylist(self.rows, schema=self.schema)
        else:
            schema = self.schema or pa.schema([])
            table = pa.Table.from_pylist([], schema=schema)
        # Atomic write: write to a sibling .tmp file then rename, so a
        # crashed run never leaves a half-written Parquet that a parallel
        # reader can pick up.
        tmp_path = parquet_path.with_suffix(parquet_path.suffix + ".tmp")
        pq.write_table(table, tmp_path, compression="zstd", compression_level=3)
        tmp_path.replace(parquet_path)

        md_header = (f"# {self.name}\n\n"
                     f"_Generated {ts} UTC by sg.lib.Report.write()_\n\n")
        md_path.write_text(md_header + (self.markdown or "_(no narrative)_\n"))
        return {"parquet": parquet_path, "markdown": md_path}


def markdown_table(rows: list[dict], columns: list[str] | None = None, max_rows: int = 50) -> str:
    """Render a small list-of-dicts as a Markdown table."""
    if not rows:
        return "_(empty)_\n"
    cols = columns or list(rows[0].keys())
    head = "| " + " | ".join(cols) + " |"
    sep  = "| " + " | ".join("---" for _ in cols) + " |"
    body = []
    for r in rows[:max_rows]:
        body.append("| " + " | ".join(_md_cell(r.get(c)) for c in cols) + " |")
    suffix = ""
    if len(rows) > max_rows:
        suffix = f"\n\n_…{len(rows) - max_rows} more rows omitted._\n"
    return "\n".join([head, sep, *body]) + suffix + "\n"


def _md_cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.hex()[:16]
    s = str(v).replace("|", "\\|").replace("\n", " ")
    return s if len(s) < 120 else s[:117] + "…"


# ----------------------------------------------------------------------
# Sensor-off mask (built by src/sensormask.py)
# ----------------------------------------------------------------------

SENSORMASK_PATH = REPORTS / "sensormask" / "sensormask.parquet"
# Per-run clock-skew offsets, emitted by scripts/consolidate_logs.py.
CLOCK_RUNS_PATH = REPORTS / "clock_skew" / "clock_runs.parquet"

SENSORMASK_SCHEMA = pa.schema([
    ("start_ts",   pa.timestamp("us", tz="UTC")),
    ("end_ts",     pa.timestamp("us", tz="UTC")),
    ("kind",       pa.string()),      # gap | run_boundary
    ("duration_s", pa.float64()),
    ("source",     pa.string()),
])


def load_sensor_mask(kinds: Iterable[str] = ("gap", "run_boundary")
                     ) -> list[tuple[_dt.datetime, _dt.datetime, str]]:
    """Masked ``(start_ts, end_ts, kind)`` intervals, sorted by start.

    Returns ``[]`` when the sensormask stage has not run, so callers work
    (unmasked) on a fresh checkout.  Stateful detectors should drop masked
    time from fit windows and reset per-entity state at each ``end_ts``.
    """
    if not SENSORMASK_PATH.exists() or SENSORMASK_PATH.stat().st_size == 0:
        return []
    t = pq.read_table(SENSORMASK_PATH, columns=["start_ts", "end_ts", "kind"])
    want = set(kinds)
    out = [(s, e, k) for s, e, k in zip(t["start_ts"].to_pylist(),
                                        t["end_ts"].to_pylist(),
                                        t["kind"].to_pylist()) if k in want]
    return sorted(out)


def mask_predicate(col: str = "ts",
                   kinds: Iterable[str] = ("gap", "run_boundary")) -> str:
    """SQL fragment that is TRUE for rows *outside* every masked interval.

    Uses a NOT EXISTS against the mask parquet so it scales to any number of
    intervals; ``TRUE`` when no mask has been built.
    """
    if not SENSORMASK_PATH.exists() or SENSORMASK_PATH.stat().st_size == 0:
        return "TRUE"
    kind_list = ", ".join(f"'{k}'" for k in kinds)
    return (f"NOT EXISTS (SELECT 1 FROM read_parquet('{SENSORMASK_PATH}') sm "
            f"WHERE sm.kind IN ({kind_list}) "
            f"AND {col} >= sm.start_ts AND {col} < sm.end_ts)")


# ----------------------------------------------------------------------
# Evaluation views (synthetic injection, kept OUT of the corpus)
# ----------------------------------------------------------------------

EVAL_DIR = OUTPUT_DIR / "eval"


def eval_inject_dir(name: str) -> Path:
    """Where ``adversarysim --inject`` writes one named injection set."""
    return EVAL_DIR / "inject" / name


def register_eval_views(con: duckdb.DuckDBPyConnection, name: str) -> None:
    """Register the canonical views, then overlay one injection set.

    ``packets`` becomes the real corpus UNION ALL the injected rows (same
    schema, same ``dt`` hive partition column), and ``eval_truth`` lists the
    injected archetypes.  The parquet corpus on disk is never modified, and
    injected rows never reach ``label_queue`` (project no-synthetic-labels
    rule): the truth table is a detector test fixture, not a label set.
    """
    d = eval_inject_dir(name)
    inj = d / "packets"
    truth = d / "truth.parquet"
    if not truth.exists() or not any(inj.glob("dt=*/*.parquet")):
        raise FileNotFoundError(f"no injection set at {d} "
                                "(run adversarysim.py --inject first)")
    register_views(con)
    con.execute(f"""
        CREATE OR REPLACE VIEW packets AS
        SELECT * FROM read_parquet('{PACKETS_GLOB}', hive_partitioning=1)
        UNION ALL BY NAME
        SELECT * FROM read_parquet('{inj / '**' / '*.parquet'}',
                                   hive_partitioning=1)
    """)
    con.execute(f"CREATE OR REPLACE VIEW eval_truth AS "
                f"SELECT * FROM read_parquet('{truth}')")


# ----------------------------------------------------------------------
# Time-window helpers
# ----------------------------------------------------------------------

def parse_date_arg(s: str | None) -> _dt.date | None:
    """Accept YYYY-MM-DD, or ``today``/``yesterday``."""
    if not s:
        return None
    s = s.strip().lower()
    today = _dt.date.today()
    if s == "today":     return today
    if s == "yesterday": return today - _dt.timedelta(days=1)
    return _dt.date.fromisoformat(s)


def date_predicate(col: str, since: _dt.date | None, until: _dt.date | None) -> str:
    """Return a SQL WHERE fragment (without leading WHERE/AND)."""
    parts = []
    if since is not None: parts.append(f"{col} >= TIMESTAMP '{since.isoformat()} 00:00:00+00'")
    if until is not None: parts.append(f"{col} <  TIMESTAMP '{(until + _dt.timedelta(days=1)).isoformat()} 00:00:00+00'")
    return " AND ".join(parts) or "TRUE"


# ----------------------------------------------------------------------
# Common argparse setup shared by analyzer CLIs
# ----------------------------------------------------------------------

def add_window_args(ap):
    ap.add_argument("--since", default=None, help="YYYY-MM-DD (inclusive)")
    ap.add_argument("--until", default=None, help="YYYY-MM-DD (inclusive)")
    ap.add_argument("--limit", type=int, default=0, help="Top-N cap on report tables.")


# ----------------------------------------------------------------------
# Quick smoke
# ----------------------------------------------------------------------

if __name__ == "__main__":
    paths = find_geolite_paths()
    print("GeoLite paths:")
    for k, v in paths.items():
        print(f"  {k}: {v}")
    print("Self IPs:", sorted(self_ips()))
    con = duck()
    register_views(con)
    for view in ("packets", "payload_blobs", "l7_events", "iocs"):
        try:
            n = con.execute(f"SELECT count(*) FROM {view}").fetchone()[0]
            print(f"  {view}: {n:,} rows")
        except Exception as e:
            print(f"  {view}: <unreadable> ({e})")

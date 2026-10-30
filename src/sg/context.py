"""
sg/context — the source-day context for calibration with context (proposal A1).

docs/NEUROMORPHIC_NEXT_PATHS.md §3 A1.  lif.calibrate compares a readout
with the reference source-days of a similar packet count only.  A1 compares
it only with reference source-days of the same kind of source as well:

  port   distinct destination ports on the day: 1, 2..10, more than 10
  l7     the most frequent l7 label of the source's packets on the day
         (none, http, tls, ssh, telnet, bittorrent, other)
  asn    the type of the source network: scanner (a published scanner
         CIDR in benignfilter), hosting, residential, other (keywords of
         the organization name; longer lists than the risk step, which
         keeps its own)
  mask   the sensor state of the day: 1 when a sensormask interval
         touches the day, else 0

``calibrate_ctx`` uses the full context when the reference has at least
MIN_REF source-days of that context.  When it has fewer, it drops the last
field and tries again (mask, then asn, then l7, then port), down to the
plain lif.calibrate on all reference source-days.  Small strata thus merge
with their parent and do not give unstable exceedance values.

Context codes are small integers (one decimal digit each), so a context key
is a 4-digit number.  This module is apart from sg/lif.py: a change here
does not make the cached LIF readouts old.
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import numpy as np

from sg import lib, lif

FIELDS = ("port", "l7", "asn", "mask")      # drop order: from the end
MIN_REF = 2000                              # source-days for a stratum

L7_CLASS = {"http": 1, "tls": 2, "ssh": 3, "telnet": 4, "bittorrent": 5}
L7_OTHER = 6
ASN_SCANNER, ASN_HOSTING, ASN_RESIDENTIAL, ASN_OTHER = 3, 2, 1, 0

# Organization keywords.  Hosting: cloud, VPS and bulletproof hosts.
HOSTING_KEYWORDS = (
    "media land", "skynet", "tamatiya", "iptransit", "mevspace",
    "layer7 networks", "iproyal", "net-surf", "ip volume", "pfcloud",
    "latitude.sh", "amazon", "google", "microsoft", "azure", "digitalocean",
    "vultr", "choopa", "linode", "akamai", "ovh", "hetzner", "alibaba",
    "tencent", "constant company", "contabo", "leaseweb", "m247",
    "hostinger", "oracle", "ionos", "scaleway", "hostwinds", "colocrossing",
    "psychz", "quadranet", "datacamp", "g-core", "gcore", "zenlayer",
    "ucloud", "huawei cloud", "frantech", "buyvm", "servers.com",
    "cloudflare", "fastly", "hosting", "datacenter", "data center", "vps")
RESIDENTIAL_KEYWORDS = (
    "comcast", "cox", "verizon", "at&t", "att services", "spectrum",
    "charter", "space exploration", "starlink", "t-mobile", "frontier",
    "centurylink", "lumen", "windstream", "mediacom", "altice", "optimum",
    "rogers", "bell canada", "shaw", "telus", "deutsche telekom",
    "vodafone", "orange", "telefonica", "jio", "airtel", "bharti",
    "telecom", "broadband", "cable", "china mobile", "china unicom",
    "chinanet", "korea telecom", "kt corporation", "sk broadband", "ntt",
    "kddi", "softbank", "chunghwa", "viettel", "vnpt", "telkom", "claro",
    "vivo", "movistar", "turk telekom", "rostelecom", "mts", "beeline")

BENIGNFILTER = lib.REPORTS / "benignfilter" / "benignfilter.parquet"


def port_class(n_ports) -> np.ndarray:
    n = np.asarray(n_ports)
    return np.where(n <= 1, 0, np.where(n <= 10, 1, 2)).astype(np.int8)


def l7_class(l7_ids) -> np.ndarray:
    out = []
    for v in l7_ids:
        if v is None or int(v) == 0:
            out.append(0)
        else:
            out.append(L7_CLASS.get(lib.L7_NAME.get(int(v), ""), L7_OTHER))
    return np.array(out, dtype=np.int8)


def asn_class(asn_org: str | None, scanner: bool) -> int:
    if scanner:
        return ASN_SCANNER
    s = (asn_org or "").lower()
    if any(k in s for k in HOSTING_KEYWORDS):
        return ASN_HOSTING
    if any(k in s for k in RESIDENTIAL_KEYWORDS):
        return ASN_RESIDENTIAL
    return ASN_OTHER


def scanner_cidr_ips() -> frozenset[str]:
    """Sources in a published scanner CIDR (benignfilter evidence 'cidr:')."""
    if not BENIGNFILTER.exists():
        return frozenset()
    con = lib.duck()
    try:
        return frozenset(r[0] for r in con.execute(
            f"SELECT src_ip FROM read_parquet('{BENIGNFILTER}') "
            "WHERE evidence LIKE '%cidr:%'").fetchall())
    finally:
        con.close()


def masked_days() -> set[_dt.date]:
    """UTC days that a sensormask interval touches."""
    out = set()
    for s, e, _ in lib.load_sensor_mask():
        d = s.astimezone(_dt.timezone.utc).date()
        last = e.astimezone(_dt.timezone.utc).date()
        while d <= last:
            out.add(d)
            d += _dt.timedelta(days=1)
    return out


def key_inputs() -> list[bytes]:
    """What a cached context depends on, other than the packets."""
    out = [Path(__file__).read_bytes()]
    for p in (BENIGNFILTER, lib.SENSORMASK_PATH):
        if p.exists():
            st = p.stat()
            out.append(f"{p.name}:{st.st_size}:{st.st_mtime_ns}".encode())
    return out


def day_context(con, day: _dt.date, scanners: frozenset[str],
                masked: set[_dt.date], geo=None) -> dict:
    """Context codes of every source of ``day`` (the ``packets`` view, NTP
    and sensormask excluded as in lif_eval.load_day).  Returns a dict with
    "ips" (sorted source list) and "ctx" (int8 array, one row per source,
    one column per FIELDS entry)."""
    from bench import arrival_series as ars
    rows = con.execute(f"""
        SELECT src_ip, count(DISTINCT dst_port) AS n_ports,
               mode(l7_proto) FILTER (WHERE l7_proto > 0) AS l7
        FROM packets
        WHERE dt = DATE '{day}' AND {ars.NOT_NTP} AND {lib.mask_predicate('ts')}
        GROUP BY src_ip ORDER BY src_ip
    """).fetchall()
    if geo is None:
        geo = lib.GeoLookup()
    ips = [r[0] for r in rows]
    ctx = np.zeros((len(rows), len(FIELDS)), dtype=np.int8)
    if rows:
        ctx[:, 0] = port_class([r[1] for r in rows])
        ctx[:, 1] = l7_class([r[2] for r in rows])
        ctx[:, 2] = [asn_class(geo.lookup(ip).asn_org, ip in scanners)
                     for ip in ips]
        ctx[:, 3] = 1 if day in masked else 0
    return {"ips": ips, "ctx": ctx}


def align(ips: list[str], ctx_ips: list[str], ctx: np.ndarray) -> np.ndarray:
    """Context rows in the order of ``ips``; a source with no context row
    gets all zeros."""
    pos = {ip: i for i, ip in enumerate(ctx_ips)}
    out = np.zeros((len(ips), len(FIELDS)), dtype=np.int8)
    idx = np.array([pos.get(ip, -1) for ip in ips], dtype=np.int64)
    ok = idx >= 0
    out[ok] = ctx[idx[ok]]
    return out


def _keys(ctx: np.ndarray, k: int) -> np.ndarray:
    if k == 0:
        return np.zeros(len(ctx), dtype=np.int64)
    w = 10 ** np.arange(k - 1, -1, -1, dtype=np.int64)
    return ctx[:, :k].astype(np.int64) @ w


def calibrate_ctx(score: np.ndarray, logn: np.ndarray, ctx: np.ndarray,
                  ref: np.ndarray, ref_logn: np.ndarray, ref_ctx: np.ndarray,
                  min_ref: int = MIN_REF) -> tuple[np.ndarray, np.ndarray]:
    """lif.calibrate inside the finest context stratum with >= min_ref
    reference source-days.  Returns (calibrated, number of context fields
    used for each row)."""
    out = np.zeros(len(score))
    level = np.zeros(len(score), dtype=np.int8)
    left = np.ones(len(score), dtype=bool)
    for k in range(len(FIELDS), -1, -1):
        if not left.any():
            break
        sk, rk = _keys(ctx, k), _keys(ref_ctx, k)
        order = np.argsort(rk, kind="stable")
        rk_s = rk[order]
        for key in np.unique(sk[left]):
            lo, hi = np.searchsorted(rk_s, key), np.searchsorted(rk_s, key, "right")
            if k and hi - lo < min_ref:
                continue
            sel = left & (sk == key)
            r = order[lo:hi]
            out[sel] = lif.calibrate(score[sel], logn[sel], ref[r], ref_logn[r])
            level[sel] = k
            left &= ~sel
    return out, level

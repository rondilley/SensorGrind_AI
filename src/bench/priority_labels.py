#!/usr/bin/env python3
"""
bench/priority_labels — analyst-priority labels made by the tools.

Neuromorphic round 2, evaluation harness v2 (docs/NEUROMORPHIC_ROUND2_PLAN.md
§3.4).  Every source that touches the honeypot is suspect, so the label is
the analyst priority, not "malicious or not", and no operator labels by hand:

  level 1  Act         exploit or credential evidence: an IOC of kind cmd,
                       file_hash, cred or mstshash; 5 or more distinct HTTP
                       URIs; a botnet family (clusterxref); or a member of a
                       telco_ss7_recon, critical_persistent_botnet or
                       rdp_credential_spray finding
  level 2  Review      not level 1, and campaign_count > 0 or a member of any
                       other correlator finding (coordinated campaigns,
                       anomalous / rare chains, fingerprint rotation, ...)
  level 3  Background  every other source

A known internet scanner (benignfilter: published scanner CIDRs, scanner
user agents, scanner ASNs) is a flag, not a level.

``first_l1_day`` is the first UTC day with IOC level-1 evidence (the URI
rule counts distinct URIs cumulatively).  Botnet and finding membership have
no day, so a source that is level 1 only through them has no first_l1_day
and is left out of the escalation label:

  escalation(score_day, horizon)  1 = first_l1_day in (D, D + horizon]
                                  0 = no level-1 evidence up to D + horizon
                                  excluded = level 1 on or before D, or
                                             level 1 with no day

The rules read IOC, payload, campaign and finding columns only; the
neuromorphic detectors read packet times and ports (feature manifests,
plan §3.2).

Output: output/reports/priority_labels/priority_labels.{parquet,md}
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys
import time
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib

OUT = lib.REPORTS / "priority_labels"
PATH = OUT / "priority_labels.parquet"
L1_IOC_KINDS = ("cmd", "file_hash", "cred", "mstshash")
L1_URIS = 5
L1_FINDINGS = ("telco_ss7_recon", "critical_persistent_botnet",
               "rdp_credential_spray")
FEATURES = ["iocs.ioc_kind", "iocs.value", "iocs.ts",
            "features.campaign_count", "features.botnet_family",
            "features.benign_org", "conclusions.finding_members"]

SCHEMA = pa.schema([
    ("src_ip",       pa.string()),
    ("level",        pa.uint8()),
    ("first_l1_day", pa.date32()),
    ("l1_reason",    pa.string()),
    ("known_scanner", pa.string()),
])


def build(snapshot: Path | None = None) -> pa.Table:
    con = lib.duck()
    lib.register_views(con)
    feat = snapshot or sorted((lib.OUTPUT_DIR / "features" / "ip").glob("dt=*"))[-1]
    kinds = ", ".join(str(lib.IOC_ID[k]) for k in L1_IOC_KINDS)
    uri = lib.IOC_ID["http_uri"]
    fm = lib.OUTPUT_DIR / "conclusions" / "finding_members.parquet"
    fi = lib.OUTPUT_DIR / "conclusions" / "findings.parquet"
    l1f = ", ".join(f"'{f}'" for f in L1_FINDINGS)
    tab = con.execute(f"""
        WITH k AS (                       -- first day of an exploit / cred IOC
            SELECT src_ip, min(CAST(timezone('UTC', ts) AS DATE)) AS d
            FROM read_parquet('{lib.IOCS_GLOB}', hive_partitioning=1)
            WHERE ioc_kind IN ({kinds}) GROUP BY src_ip
        ), u0 AS (                        -- first day of each distinct URI
            SELECT src_ip, value, min(CAST(timezone('UTC', ts) AS DATE)) AS d
            FROM read_parquet('{lib.IOCS_GLOB}', hive_partitioning=1)
            WHERE ioc_kind = {uri} GROUP BY ALL
        ), u AS (                         -- day the 5th distinct URI is seen
            SELECT src_ip, d FROM (
                SELECT src_ip, d, row_number() OVER (PARTITION BY src_ip
                                                     ORDER BY d) AS n
                FROM u0) WHERE n = {L1_URIS}
        ), m AS (
            SELECT m.src_ip,
                   bool_or(f.pattern_id IN ({l1f})) AS l1_find,
                   true AS any_find
            FROM read_parquet('{fm}') m JOIN read_parquet('{fi}') f
                 USING (finding_id) GROUP BY m.src_ip
        ), f AS (
            SELECT src_ip, campaign_count, botnet_family, benign_org
            FROM read_parquet('{feat}/**/*.parquet')
        )
        SELECT f.src_ip,
               least(k.d, u.d) AS first_l1_day,
               k.d IS NOT NULL AS l1_ioc, u.d IS NOT NULL AS l1_uri,
               coalesce(f.botnet_family, '') <> '' AS l1_botnet,
               coalesce(m.l1_find, false) AS l1_find,
               coalesce(f.campaign_count, 0) > 0 OR coalesce(m.any_find, false) AS l2,
               nullif(f.benign_org, '') AS known_scanner
        FROM f LEFT JOIN k USING (src_ip) LEFT JOIN u USING (src_ip)
               LEFT JOIN m USING (src_ip)
    """).to_arrow_table()
    con.close()
    reasons = []
    level = np.full(tab.num_rows, 3, dtype=np.uint8)
    cols = {c: tab[c].to_numpy(zero_copy_only=False)
            for c in ("l1_ioc", "l1_uri", "l1_botnet", "l1_find", "l2")}
    names = {"l1_ioc": "ioc", "l1_uri": "uris", "l1_botnet": "botnet",
             "l1_find": "finding"}
    l1 = cols["l1_ioc"] | cols["l1_uri"] | cols["l1_botnet"] | cols["l1_find"]
    level[cols["l2"] & ~l1] = 2
    level[l1] = 1
    for i in range(tab.num_rows):
        reasons.append(",".join(n for c, n in names.items() if cols[c][i]))
    return pa.table({"src_ip": tab["src_ip"],
                     "level": pa.array(level, pa.uint8()),
                     "first_l1_day": tab["first_l1_day"].cast(pa.date32()),
                     "l1_reason": pa.array(reasons, pa.string()),
                     "known_scanner": tab["known_scanner"]}, schema=SCHEMA)


def load() -> pa.Table:
    return pq.read_table(PATH)


def escalation(labels: pa.Table, score_day: _dt.date, horizon: int = 30
               ) -> dict[str, int]:
    """src_ip -> 1/0 escalation label for one score day (see module doc).
    Sources that are excluded are not in the dict."""
    ip = labels["src_ip"].to_pylist()
    lv = labels["level"].to_numpy()
    d = labels["first_l1_day"].to_pylist()
    end = score_day + _dt.timedelta(days=horizon)
    out = {}
    for s, l, f in zip(ip, lv, d):
        if l == 1 and f is None:
            continue                      # level 1 with no day
        if f is None:
            out[s] = 0
        elif f <= score_day:
            continue                      # already level 1
        else:
            out[s] = int(f <= end)
    return out


def run(args) -> None:
    t0 = time.time()
    tab = build()
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = PATH.with_suffix(".parquet.tmp")
    pq.write_table(tab, tmp, compression="zstd")
    tmp.replace(PATH)
    lv = tab["level"].to_numpy()
    sc = np.array([s is not None for s in tab["known_scanner"].to_pylist()])
    rs = tab["l1_reason"].to_pylist()
    md = [f"- {tab.num_rows:,} sources (feature snapshot); run time "
          f"{time.time() - t0:.0f} s", "",
          "| level | sources | known scanners |", "| --- | ---: | ---: |"]
    for l, name in ((1, "1 Act"), (2, "2 Review"), (3, "3 Background")):
        md.append(f"| {name} | {(lv == l).sum():,} | {(sc & (lv == l)).sum():,} |")
    md += ["", "Level 1 conditions (a source can have more than one):", "",
           "| condition | sources |", "| --- | ---: |"]
    for k in ("ioc", "uris", "botnet", "finding"):
        md.append(f"| {k} | {sum(1 for r in rs if k in r.split(',')):,} |")
    nd = sum(1 for d, l in zip(tab["first_l1_day"].to_pylist(), lv)
             if l == 1 and d is None)
    md += ["", f"Level 1 sources with no first day (left out of the "
           f"escalation label): {nd:,}", "", "Feature manifest: " +
           ", ".join(f"`{f}`" for f in FEATURES)]
    (OUT / "priority_labels.md").write_text("# priority_labels\n\n" +
                                            "\n".join(md) + "\n")
    print(f"[priority_labels] wrote {PATH} ({time.time() - t0:.0f}s)",
          file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    run(ap.parse_args())
    return 0


if __name__ == "__main__":
    sys.exit(main())

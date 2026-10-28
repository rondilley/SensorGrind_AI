#!/usr/bin/env python3
"""
bench/harness2 — evaluation harness v2 for the neuromorphic round 2.

docs/NEUROMORPHIC_ROUND2_PLAN.md §3.  The gate harnesses (lif_eval,
stdp_eval, hdc_eval, baselines) call ``truth_ranks`` with their scores and
``write_ranks`` to keep one row per (detector, injected source):

  rank_clean  rank among the recorded sources plus the sources of this
              archetype only (the lif_eval.eval_clean population)
  rank_all    rank among every scored source of the day, all injected
              archetypes included (an operator's alarm budget)
  NaN rank    the source is not in the scored population (too few packets):
              a miss at every budget

``--summary MODULE NAME ...`` pools the rank files of saved sets:

  * recall at each budget k over ALL injected sources of an archetype, with
    a Wilson 95 % interval and a cluster bootstrap 95 % interval over sets
  * control false-flag rate at each k (control_replay)
  * the rule-1 gate of §3.7: a detector passes against a twin when its
    interval lies above the twin's interval at every k (MIN_SETS sets or
    more)
  * Jaccard agreement of the found sources (k = 100) between detectors
  * dev / test split: sets with a day before DEV_END are development sets
    and are reported apart from the test sets

``freeze`` records the SHA-256 of detector files and the run settings.
``FEATURES`` is the feature manifest of each detector (plan §3.2); the
event catalogue removes an event from a detector's test when the analyzer
that found the event shares a feature with the detector.

Output: output/reports/harness2/<module>/<NAME>_ranks.parquet,
        output/reports/harness2/<module>_summary[_<TAG>].{parquet,md},
        output/reports/harness2/freeze_<tag>.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib
from bench import baselines as bl

OUT = lib.REPORTS / "harness2"
DEV_END = _dt.date(2024, 8, 1)       # plan §3.1: development days are before
KS = (10, 50, 100)
BOOT = 2000
MIN_SETS = 10                        # gate rule 1 needs this many sets

# Feature manifest of each detector family (plan §3.2).
FEATURES: dict[str, set[str]] = {
    "lif": {"packets.ts", "packets.src_ip"},
    "pacing": {"packets.ts", "packets.src_ip"},
    "hawkes": {"packets.ts", "packets.src_ip"},
    "stdp": {"packets.dst_port", "packets.src_ip"},
    "kmeans": {"packets.dst_port", "packets.src_ip"},
    "hdc": {"packets.ts", "packets.dst_port", "packets.tcp_flags",
            "packets.proto", "packets.src_ip"},
    "rff": {"packets.ts", "packets.dst_port", "packets.tcp_flags",
            "packets.proto", "packets.src_ip"},
    "h1": {"packets.ts", "packets.dst_port", "packets.tcp_flags",
           "packets.proto", "packets.src_ip"},
    "priority_labels": {"iocs.ioc_kind", "iocs.value", "iocs.ts",
                        "features.campaign_count", "features.botnet_family",
                        "features.benign_org", "conclusions.finding_members"},
}

RANK_SCHEMA = pa.schema([
    ("eval_name",  pa.string()),
    ("day",        pa.date32()),
    ("detector",   pa.string()),
    ("archetype",  pa.string()),
    ("is_control", pa.bool_()),
    ("src_ip",     pa.string()),
    ("rank_clean", pa.float64()),
    ("rank_all",   pa.float64()),
    ("pop_clean",  pa.uint32()),
    ("pop_all",    pa.uint32()),
])

SUMMARY_SCHEMA = pa.schema([
    ("module",     pa.string()),
    ("split",      pa.string()),
    ("detector",   pa.string()),
    ("archetype",  pa.string()),
    ("is_control", pa.bool_()),
    ("ranking",    pa.string()),
    ("k",          pa.uint32()),
    ("n_sets",     pa.uint32()),
    ("n_truth",    pa.uint32()),
    ("hits",       pa.uint32()),
    ("recall",     pa.float64()),
    ("wilson_lo",  pa.float64()),
    ("wilson_hi",  pa.float64()),
    ("boot_lo",    pa.float64()),
    ("boot_hi",    pa.float64()),
])


def shared_features(detector: str, analyzer_features: set[str]) -> set[str]:
    """Features that a detector family and an event's analyzer share."""
    fam = next((f for f in FEATURES if detector.startswith(f)), detector)
    return FEATURES.get(fam, set()) & analyzer_features


# ---------------------------------------------------------------- ranks

def truth_ranks(name: str, day: _dt.date, ips: list[str], scores: dict,
                truth: list[dict], seed: int) -> list[dict]:
    """One row per (detector, injected source); see the module doc."""
    pos = {ip: i for i, ip in enumerate(ips)}
    src = [t for t in truth if t["level"] == "source"]
    injected = {t["src_ip"] for t in src}
    real = np.flatnonzero([ip not in injected for ip in ips])
    groups: dict[tuple, list[dict]] = {}
    for t in src:
        groups.setdefault((t["archetype"], t["is_control"]), []).append(t)
    out = []
    for det, s in scores.items():
        s = np.asarray(s, dtype=float)
        r_all = bl.ranks_desc(s, seed)
        for (arch, ctrl), ts in groups.items():
            idx = np.array([pos[t["src_ip"]] for t in ts if t["src_ip"] in pos],
                           dtype=np.int64)
            pop = np.concatenate([real, idx])
            r_clean = bl.ranks_desc(s[pop], seed)[len(real):] if len(idx) else []
            rc = dict(zip((ips[i] for i in idx), r_clean))
            for t in ts:
                ip = t["src_ip"]
                out.append({
                    "eval_name": name, "day": day, "detector": det,
                    "archetype": arch, "is_control": ctrl, "src_ip": ip,
                    "rank_clean": float(rc[ip]) if ip in rc else np.nan,
                    "rank_all": float(r_all[pos[ip]]) if ip in pos else np.nan,
                    "pop_clean": len(pop), "pop_all": len(ips),
                })
    return out


def write_ranks(module: str, name: str, rows: list[dict]) -> Path:
    d = OUT / module
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{name}_ranks.parquet"
    tmp = path.with_suffix(".parquet.tmp")
    pq.write_table(pa.Table.from_pylist(rows, schema=RANK_SCHEMA), tmp,
                   compression="zstd")
    tmp.replace(path)
    return path


# ---------------------------------------------------------------- stats

def wilson(h: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (np.nan, np.nan)
    p = h / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    w = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - w) / d, (c + w) / d)


def boot_ci(hits: np.ndarray, n: np.ndarray, seed: int = 0,
            reps: int = BOOT) -> tuple[float, float]:
    """Cluster bootstrap over sets of pooled recall sum(hits) / sum(n)."""
    if len(n) == 0 or n.sum() == 0:
        return (np.nan, np.nan)
    rng = np.random.default_rng(seed)
    pick = rng.integers(0, len(n), size=(reps, len(n)))
    r = hits[pick].sum(1) / np.maximum(n[pick].sum(1), 1)
    return (float(np.quantile(r, 0.025)), float(np.quantile(r, 0.975)))


def summary(module: str, names: list[str], twins: dict[str, list[str]],
            ks=KS, tag: str = "") -> None:
    tabs = [pq.read_table(OUT / module / f"{n}_ranks.parquet") for n in names
            if (OUT / module / f"{n}_ranks.parquet").exists()]
    t = pa.concat_tables(tabs).to_pandas()
    t["split"] = np.where(t["day"] < DEV_END, "dev", "test")
    rows = []
    found: dict[tuple, set] = {}
    for (split, det, arch, ctrl), g in t.groupby(["split", "detector",
                                                  "archetype", "is_control"]):
        sets = g["eval_name"].to_numpy()
        uniq = np.unique(sets)
        for ranking in ("clean", "all"):
            rk = g[f"rank_{ranking}"].to_numpy()
            for k in ks:
                hit = np.nan_to_num(rk, nan=np.inf) <= k
                h_set = np.array([hit[sets == s].sum() for s in uniq])
                n_set = np.array([(sets == s).sum() for s in uniq])
                h, n = int(hit.sum()), len(hit)
                wl, wh = wilson(h, n)
                bl_, bh = boot_ci(h_set, n_set, seed=k)
                rows.append({"module": module, "split": split, "detector": det,
                             "archetype": arch, "is_control": bool(ctrl),
                             "ranking": ranking, "k": k, "n_sets": len(uniq),
                             "n_truth": n, "hits": h, "recall": h / n,
                             "wilson_lo": wl, "wilson_hi": wh,
                             "boot_lo": bl_, "boot_hi": bh})
                if ranking == "clean" and k == max(ks):
                    found[(split, det, arch)] = set(
                        zip(g["eval_name"][hit], g["src_ip"][hit]))
    rec = {(r["split"], r["detector"], r["archetype"], r["ranking"], r["k"]): r
           for r in rows}
    dets = sorted(t["detector"].unique())
    md = [f"- module `{module}`: {t['eval_name'].nunique()} sets "
          f"({(t.groupby('eval_name')['split'].first() == 'dev').sum()} dev, "
          f"{(t.groupby('eval_name')['split'].first() == 'test').sum()} test); "
          f"development days are before {DEV_END}", "",
          "Recall is over all injected sources of the archetype. A source "
          "that is not in the scored population is a miss. `clean`: rank "
          "among the recorded sources plus the sources of the archetype. "
          "`all`: rank among all sources of the day. Intervals: cluster "
          "bootstrap over sets (95 %).", ""]
    for split in ("test", "dev"):
        sub = [r for r in rows if r["split"] == split]
        if not sub:
            continue
        archs = sorted({(r["archetype"], r["is_control"]) for r in sub})
        for ranking in ("clean", "all"):
            md += [f"## {split} sets, ranking `{ranking}`", ""]
            for k in ks:
                md += [f"### k = {k}", "",
                       "| archetype | n | " + " | ".join(dets) + " |",
                       "| --- | ---: |" + " ---: |" * len(dets)]
                for arch, ctrl in archs:
                    cells, n = [], ""
                    for d in dets:
                        r = rec.get((split, d, arch, ranking, k))
                        if r is None or bool(r["is_control"]) != ctrl:
                            cells.append("")
                            continue
                        n = r["n_truth"]
                        cells.append(f"{r['recall']:.2f} [{r['boot_lo']:.2f}, "
                                     f"{r['boot_hi']:.2f}]")
                    md.append(f"| {arch}{' (control)' if ctrl else ''} | {n} | "
                              + " | ".join(cells) + " |")
                md.append("")
        # rule-1 gate: primary interval above each twin interval at every k
        md += [f"## Gate rule 1 ({split} sets, ranking `clean`)", "",
               "| primary | twin | archetype | result |", "| --- | --- | --- | --- |"]
        for prim, tw in twins.items():
            for twin in tw:
                for arch, ctrl in archs:
                    if ctrl:
                        continue
                    a = [rec.get((split, prim, arch, "clean", k)) for k in ks]
                    b = [rec.get((split, twin, arch, "clean", k)) for k in ks]
                    if None in a or None in b:
                        continue
                    if min(x["n_sets"] for x in a + b) < MIN_SETS:
                        md.append(f"| {prim} | {twin} | {arch} | too few sets |")
                        continue
                    above = all(x["boot_lo"] > y["boot_hi"] for x, y in zip(a, b))
                    below = all(x["boot_hi"] < y["boot_lo"] for x, y in zip(a, b))
                    res = "pass" if above else ("twin better" if below else "no difference")
                    md.append(f"| {prim} | {twin} | {arch} | {res} |")
        md += ["", f"## Jaccard of the found sources at k = {max(ks)} "
               f"({split} sets)", "", "| archetype | detector A | detector B | "
               "Jaccard | only A | only B |", "| --- | --- | --- | ---: | ---: | ---: |"]
        for prim, tw in twins.items():
            for twin in tw:
                for arch, ctrl in archs:
                    A = found.get((split, prim, arch))
                    B = found.get((split, twin, arch))
                    if ctrl or A is None or B is None or not (A | B):
                        continue
                    md.append(f"| {arch} | {prim} | {twin} | "
                              f"{len(A & B) / len(A | B):.2f} | {len(A - B)} | "
                              f"{len(B - A)} |")
        md.append("")
    paths = lib.Report(name="harness2", rows=rows, schema=SUMMARY_SCHEMA,
                       markdown="\n".join(md) + "\n").write(
        suffix=f"{module}_summary" + (f"_{tag}" if tag else ""))
    print(f"[harness2] wrote {paths['markdown']}", file=sys.stderr)


# ---------------------------------------------------------------- arrival

# Analyzer features of each event source and the arrival detectors (keys
# such as ts and src_ip are not features).  pay_pkts counts payload packets;
# the payload waves use payload hash identity: related, not shared.
ARRIVAL_FEATURES = {"arrival.pkts", "arrival.n_src", "arrival.n_24",
                    "arrival.new_src", "arrival.n_ports", "arrival.pay_pkts",
                    "arrival.no_port", "arrival.port_buckets",
                    "arrival.syn_share"}
EVENT_FEATURES = {"payload_wave": {"packets.payload_sha256"},
                  "phase2": {"arrival.new_src"}}
DETECTOR_EXTRA = {"tail5x": {"arrival.new_src"}}   # same rule as phase2
EVENT_JOIN_S = 3600
EVENT_WINDOW_S = 3600


def arrival_events() -> list[dict]:
    """Launch clusters of the coordination payload waves, plus E1 and E3."""
    from bench import arrival_eval as ae
    w = pq.read_table(lib.OUTPUT_DIR / "patterns" / "coordination" /
                      "payload_waves.parquet",
                      columns=["launch_ts", "ip_count", "is_campaign"]).to_pylist()
    t = sorted((r["launch_ts"].timestamp(), r["ip_count"]) for r in w
               if r["is_campaign"] and r["launch_ts"] is not None)
    ev, cur = [], None
    for ts, n in t:
        if cur and ts - cur["last"] <= EVENT_JOIN_S:
            cur["last"], cur["n_waves"], cur["ips"] = ts, cur["n_waves"] + 1, cur["ips"] + n
        else:
            cur = {"source": "payload_wave", "start": ts, "last": ts,
                   "n_waves": 1, "ips": n}
            ev.append(cur)
    for e in ev:
        e["end"] = e["last"] + EVENT_WINDOW_S
    for k in ("E1", "E3"):
        a, b = (_dt.datetime.fromisoformat(x).timestamp() for x in ae.EVENTS[k])
        ev.append({"source": "phase2", "start": a, "last": a, "end": b,
                   "n_waves": 0, "ips": 0, "name": k})
    for i, e in enumerate(ev):
        e.setdefault("name", f"W{i + 1:03d}")
        e["day"] = _dt.datetime.fromtimestamp(e["start"], _dt.timezone.utc).date()
    return ev


def arrival(rates=(1, 10, 100), seed: int = 0) -> None:
    """Event-level recall of the frozen first-round arrival scores."""
    from bench import arrival_eval as ae
    st = pq.read_table(ae.OUT / "arrival_scores_full.parquet")
    minute = st["minute"].cast(pa.int64()).to_numpy() / 1e6
    sc = {k: st[k].to_numpy(zero_copy_only=False).astype(float)
          for k in ae.DETECTORS}
    common = np.all(np.stack([np.isfinite(sc[k]) for k in ae.GATE]), axis=0)
    ev = arrival_events()
    rows, md = [], []
    for e in ev:
        lo, hi = np.searchsorted(minute, [e["start"] - 59, e["end"]])
        e["win"] = np.arange(lo, hi)[common[lo:hi]]
    used = [e for e in ev if len(e["win"])]
    md += [f"- events: {len(ev)} ({sum(e['source'] == 'payload_wave' for e in ev)} "
           f"payload-wave launch clusters, joined within {EVENT_JOIN_S // 60} "
           f"min, window {EVENT_WINDOW_S // 60} min after the last launch; E1, "
           f"E3). {len(used)} have scored minutes.",
           f"- scored minutes (all gate detectors): {int(common.sum()):,}; "
           f"development days are before {DEV_END}",
           "- features: the arrival detectors read the per-minute counts "
           "(packets, sources, /24s, new sources, ports, payload packets, "
           "port buckets, SYN share). The payload waves come from payload "
           "hash identity, so they share no feature. `tail5x` and E1/E3 come "
           "from the same new-source rule, so `tail5x` is not scored on E1 "
           "and E3.", "",
           "Chance: the expected recall of a random score at the same alarm "
           "rate. Intervals: bootstrap over events (95 %).", ""]
    for split in ("test", "dev"):
        sub = [e for e in used if (e["day"] < DEV_END) == (split == "dev")]
        if not sub:
            continue
        md += [f"## {split} events ({len(sub)})", "",
               "| detector | " + " | ".join(f"{r}/day recall [95 %]" for r in rates)
               + " | median delay at 10/day (min) |",
               "| --- |" + " ---: |" * (len(rates) + 1)]
        chance = []
        for r in rates:
            q = r / 1440
            chance.append(float(np.mean([1 - (1 - q) ** len(e["win"]) for e in sub])))
        md.append("| chance | " + " | ".join(f"{c:.2f}" for c in chance) + " | |")
        for k in ae.DETECTORS:
            v = np.where(common, sc[k], np.nan)
            fin = np.isfinite(v)
            feats = ARRIVAL_FEATURES | DETECTOR_EXTRA.get(k, set())
            mine = [e for e in sub if not (EVENT_FEATURES[e["source"]]
                                           & DETECTOR_EXTRA.get(k, set()))]
            cells, delay = [], ""
            for r in rates:
                th = np.quantile(v[fin], 1 - r / 1440) if fin.any() else np.inf
                hit = np.array([bool((v[e["win"]] >= th).any()) for e in mine])
                rec = hit.mean() if len(hit) else np.nan
                rng = np.random.default_rng(seed + r)
                bs = [hit[rng.integers(0, len(hit), len(hit))].mean()
                      for _ in range(BOOT)] if len(hit) else [np.nan]
                lo_, hi_ = np.quantile(bs, [0.025, 0.975])
                cells.append(f"{rec:.2f} [{lo_:.2f}, {hi_:.2f}]")
                rows.append({"module": "arrival", "split": split, "detector": k,
                             "archetype": "recorded_event", "is_control": False,
                             "ranking": f"rate{r}", "k": r, "n_sets": len(mine),
                             "n_truth": len(mine), "hits": int(hit.sum()),
                             "recall": float(rec), "wilson_lo": wilson(int(hit.sum()), len(hit))[0],
                             "wilson_hi": wilson(int(hit.sum()), len(hit))[1],
                             "boot_lo": float(lo_), "boot_hi": float(hi_)})
                if r == 10:
                    d = [(minute[e["win"]][v[e["win"]] >= th].min() - e["start"]) / 60
                         for e, h in zip(mine, hit) if h]
                    delay = f"{max(0.0, float(np.median(d))):.0f}" if d else "-"
            md.append(f"| {k} | " + " | ".join(cells) + f" | {delay} |")
        md.append("")
    md += ["## Events", "", "| event | source | UTC start | waves | IPs | scored minutes |",
           "| --- | --- | --- | ---: | ---: | ---: |"]
    for e in ev:
        md.append(f"| {e['name']} | {e['source']} | "
                  f"{_dt.datetime.fromtimestamp(e['start'], _dt.timezone.utc):%Y-%m-%d %H:%M} | "
                  f"{e['n_waves']} | {e['ips']:,} | {len(e['win'])} |")
    paths = lib.Report(name="harness2", rows=rows, schema=SUMMARY_SCHEMA,
                       markdown="\n".join(md) + "\n").write(suffix="arrival_events")
    print(f"[harness2] wrote {paths['markdown']}", file=sys.stderr)


# ---------------------------------------------------------------- freeze

def freeze(tag: str, files: list[str], settings: dict) -> Path:
    """Record the SHA-256 of the detector files and the run settings."""
    root = Path(__file__).resolve().parents[2]
    rec = {"tag": tag, "created": _dt.datetime.now(_dt.timezone.utc).isoformat(),
           "dev_end": DEV_END.isoformat(), "settings": settings,
           "sha256": {f: hashlib.sha256((root / f).read_bytes()).hexdigest()
                      for f in files}}
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"freeze_{tag}.json"
    path.write_text(json.dumps(rec, indent=2) + "\n")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--summary", nargs="+", metavar=("MODULE", "NAME"),
                   help="MODULE then the set names")
    g.add_argument("--arrival", action="store_true",
                   help="event-level recall of the frozen arrival scores")
    ap.add_argument("--twins", default="{}",
                    help='JSON {"primary": ["twin", ...]} for the gate rows')
    ap.add_argument("--tag", default="",
                    help="with --summary: write <module>_summary_<TAG>.* "
                         "(keeps the main summary of a module)")
    args = ap.parse_args()
    if args.arrival:
        arrival()
        return 0
    module, names = args.summary[0], args.summary[1:]
    summary(module, names, json.loads(args.twins), tag=args.tag)
    return 0


if __name__ == "__main__":
    sys.exit(main())

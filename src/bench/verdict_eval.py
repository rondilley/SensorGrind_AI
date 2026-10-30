#!/usr/bin/env python3
"""
bench/verdict_eval - measure the deterministic verdicts (conclusions/verdict.py)
against the cached LLM conclusions (conclusions.parquet).  Makes no API calls.

Measures
--------
  coverage      share of findings with a verdict other than `unclassified`
  agreement     rule verdict == the LLM verdict class, per finding
                  strict:  the LLM class as written
                  root:    an LLM "BitTorrent DRDoS / poisoning" verdict counts
                           as benign_p2p (same root cause, BitTorrent peers)
  determinism   five in-process builds give identical rows (sha256)
  size          verdicts.md bytes vs conclusions.md bytes

The LLM verdict class comes from an ordered regex table (OPUS_CLASSES) over
the cached ai_threat_model text, so this mapping is deterministic too.  The
LLM output is a weak reference: cards with the same facts got different
verdicts.  Every disagreement is listed, so a reader can judge each one.

Outputs: output/reports/verdict_eval/verdict_eval.{md,json}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib
from conclusions import verdict

OUT = lib.REPORTS / "verdict_eval"
CONCL = verdict.OUT_DIR / "conclusions.parquet"

BENIGN = re.compile(r"\bnot an attack\b|\bno attack\b|^\W*none\b|\bbenign\b|"
                    r"not a directed attack", re.I)
P2P = re.compile(r"bittorrent|torrent|\bp2p\b|peer[- ]list|swarm", re.I)
SCANNER = re.compile(r"research scann|internet[- ]measurement|shodan|censys|"
                     r"shadowserver", re.I)

# The LLM text often names several intents ("VNC discovery and credential
# spray").  Its class is the intent that comes FIRST in the text (the
# headline claim); ties go to the order of this table.
OPUS_CLASSES: list[tuple[str, re.Pattern]] = [
    ("credential_attack", re.compile(r"credential|brute|password|spray", re.I)),
    ("exploit_attempt", re.compile(r"exploit|CVE-\d|\bRCE\b|remote code|dropper|"
                                   r"recruitment|command injection|cryptojack",
                                   re.I)),
    ("hostile_infrastructure", re.compile(r"bulletproof|fast-flux|proxyware|"
                                          r"residential[- ]proxy", re.I)),
    ("protocol_anomaly", re.compile(r"tunnel|covert|spoof|flood|amplification|"
                                    r"reflection|DDoS", re.I)),
    ("service_recon", re.compile(r"recon|scan|enumerat|discover|fingerprint|"
                                 r"sweep|harvest", re.I)),
]


def opus_class(text: str) -> str:
    t = text or ""
    if BENIGN.search(t):
        if SCANNER.search(t):
            return "research_scanner"
        return "benign_p2p" if P2P.search(t) else "benign_other"
    if P2P.search(t):
        return "p2p_attack"
    hits = [(m.start(), i, cls) for i, (cls, rx) in enumerate(OPUS_CLASSES)
            if (m := rx.search(t))]
    return min(hits)[2] if hits else "other"


def _rows_sha(rows: list[dict]) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def determinism(runs: int = 5) -> tuple[bool, str, str]:
    shas = []
    for _ in range(runs):
        con = lib.duck(memory_limit="8GB")
        shas.append(_rows_sha(verdict.build(con)))
        con.close()
    return len(set(shas)) == 1, shas[0], shas[-1]


def evaluate() -> dict:
    v = {r["finding_id"]: r for r in pq.read_table(
        verdict.OUT_DIR / "verdicts.parquet").to_pylist()}
    cards = pq.read_table(CONCL, columns=["finding_id", "pattern_id",
                                          "ai_threat_model", "ai_title"]).to_pylist()
    c = {r["finding_id"]: r for r in cards}
    # A card made before a finding_id change (2026-10-30: the HTTP campaign
    # sample was unsorted, so its id hash changed each run) still matches on
    # pattern_id when that pattern_id occurs once on each side.
    vp = Counter(r["pattern_id"] for r in v.values())
    cp = Counter(r["pattern_id"] for r in cards)
    by_pat = {r["pattern_id"]: r for r in cards if cp[r["pattern_id"]] == 1}
    for fid, r in v.items():
        if fid not in c and vp[r["pattern_id"]] == 1 and r["pattern_id"] in by_pat:
            c[fid] = by_pat[r["pattern_id"]]
    pairs = []
    for fid in sorted(set(v) & set(c)):
        oc = opus_class(c[fid]["ai_threat_model"])
        pairs.append({"finding_id": fid, "pattern": v[fid]["pattern"],
                      "rule": v[fid]["verdict"], "rule_id": v[fid]["rule_id"],
                      "why": v[fid]["why"], "opus": oc,
                      "opus_text": (c[fid]["ai_threat_model"] or "")[:160]})
    n = len(pairs)
    strict = sum(p["rule"] == p["opus"] for p in pairs)
    root = sum(p["rule"] == p["opus"]
               or (p["rule"] == "benign_p2p" and p["opus"] == "p2p_attack")
               for p in pairs)
    classified = sum(r["verdict"] != "unclassified" for r in v.values())
    md_v = (verdict.OUT_DIR / "verdicts.md").stat().st_size
    md_c = (verdict.OUT_DIR / "conclusions.md").stat().st_size
    return {
        "findings": len(v), "compared": n,
        "coverage": round(classified / len(v), 4) if v else 0.0,
        "agree_strict": strict, "agree_root": root,
        "agree_strict_pct": round(strict / n, 4) if n else 0.0,
        "agree_root_pct": round(root / n, 4) if n else 0.0,
        "confusion": Counter(f"{p['rule']} | {p['opus']}" for p in pairs),
        "verdicts_md_bytes": md_v, "conclusions_md_bytes": md_c,
        "pairs": pairs,
    }


def render_md(res: dict) -> str:
    L = ["# Verdict evaluation (deterministic rules vs cached LLM cards)", "",
         f"- findings: {res['findings']}; compared with an LLM card: "
         f"{res['compared']}",
         f"- coverage (not unclassified): {res['coverage']:.1%}",
         f"- agreement, strict: {res['agree_strict']}/{res['compared']} "
         f"({res['agree_strict_pct']:.1%})",
         f"- agreement, root cause (LLM BitTorrent attack = benign_p2p): "
         f"{res['agree_root']}/{res['compared']} ({res['agree_root_pct']:.1%})",
         f"- determinism: {'identical' if res['deterministic'] else 'DIFFERENT'} "
         f"(sha256 {res['sha'][:16]})",
         f"- size: verdicts.md {res['verdicts_md_bytes']:,} bytes; "
         f"conclusions.md {res['conclusions_md_bytes']:,} bytes", "",
         "## Confusion (rule verdict | LLM class)", "",
         "| rule | LLM | findings |", "| --- | --- | ---: |"]
    for k, n in sorted(res["confusion"].items(), key=lambda kv: -kv[1]):
        a, b = k.split(" | ")
        L.append(f"| {a} | {b} | {n} |")
    L += ["", "## Disagreements", "",
          "| finding | rule | why | LLM | LLM threat model |",
          "| --- | --- | --- | --- | --- |"]
    for p in res["pairs"]:
        if p["rule"] != p["opus"]:
            cells = [p["finding_id"], p["rule"], p["why"], p["opus"], p["opus_text"]]
            L.append("| " + " | ".join(str(x).replace("|", "\\|").replace("\n", " ")
                                       for x in cells) + " |")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.parse_args()
    if not CONCL.exists() or not (verdict.OUT_DIR / "verdicts.parquet").exists():
        print("[verdict_eval] need conclusions.parquet and verdicts.parquet",
              file=sys.stderr)
        return 2
    res = evaluate()
    res["deterministic"], res["sha"], _ = determinism()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "verdict_eval.md").write_text(render_md(res))
    (OUT / "verdict_eval.json").write_text(json.dumps(
        {k: v for k, v in res.items() if k != "pairs"}, indent=2, default=dict))
    print(f"[verdict_eval] coverage {res['coverage']:.1%}; agreement strict "
          f"{res['agree_strict_pct']:.1%}, root {res['agree_root_pct']:.1%}; "
          f"deterministic={res['deterministic']}", file=sys.stderr)
    return 0 if res["deterministic"] else 1


if __name__ == "__main__":
    sys.exit(main())

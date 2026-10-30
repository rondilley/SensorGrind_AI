#!/usr/bin/env python3
"""
bench/compute_metrics — quantitative baseline metrics for the pipeline.

The project's efficacy was previously qualitative (operator review + multi-AI
aireview).  This stage emits *numbers* so we can tell whether a change (e.g.
payload-embedding pattern mining) actually moved the needle, instead of
inheriting "+20-50%" claims from the literature unverified.

Two kinds of metric:

  1. **Label-free coverage / health** (computed every run, no ground truth):
       - finding_evidence_coverage   findings carrying evidence_refs
       - finding_narrative_coverage  findings with an LLM narrative
       - risk_tier_coverage          scored IPs that got a non-empty tier
       - payload_signal_coverage     payload blobs in non-singleton clusters
                                     (singletons are the noise floor)
       - attack_technique_count      distinct ATT&CK techniques surfaced
     These are health signals: a regression (coverage drops) is a smell.

  2. **Operator-labeled precision** (optional):
       --export-labels N writes output/eval/label_queue.csv (a real sample of
       findings) for the operator to mark verdict=signal|noise|unsure.  When
       output/eval/label_queue_labeled.csv exists, precision = signal/(signal+
       noise) is computed.  We never fabricate labels — precision is absent
       until the operator fills the queue (see project no-synthetic-data rule).

Output: output/eval/metrics_<UTC-date>.json + output/eval/metrics.md (latest).
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import sys
from pathlib import Path

import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib

EVAL_DIR = lib.OUTPUT_DIR / "eval"
FINDINGS   = lib.OUTPUT_DIR / "conclusions" / "findings.parquet"
CONCLUSIONS = lib.OUTPUT_DIR / "conclusions" / "conclusions.parquet"
VERDICTS   = lib.OUTPUT_DIR / "conclusions" / "verdicts.parquet"
TRAFFICPRINT = lib.REPORTS / "trafficprint" / "trafficprint.parquet"
ATTACKMAP  = lib.REPORTS / "attackmap" / "attackmap.parquet"
HTTP_PATTERNS_SUMMARY = lib.REPORTS / "http_patterns" / "summary.json"
STORYLINES_SUMMARY = lib.OUTPUT_DIR / "conclusions" / "storylines" / "summary.json"
RISK_GLOB  = lib.OUTPUT_DIR / "risk" / "ip_risk"
LABEL_QUEUE = EVAL_DIR / "label_queue.csv"
LABEL_DONE  = EVAL_DIR / "label_queue_labeled.csv"


# ---------------------------------------------------------------- pure helpers
# Kept side-effect-free and list-based so they unit-test without the corpus.

def fraction(numer: float, denom: float) -> float | None:
    """Safe ratio: None when denom is 0 (metric undefined, not 0%)."""
    return None if not denom else round(numer / denom, 4)


def nonempty_coverage(values: list) -> float | None:
    """Fraction of values that are present and non-empty (str/list/bytes)."""
    n = len(values)
    if not n:
        return None
    have = sum(1 for v in values if v not in (None, "", b"", [], ()))
    return fraction(have, n)


def precision_from_labels(verdicts: list[str]) -> dict:
    """Operator-labeled precision proxy. verdict in {signal,noise,unsure}."""
    v = [s.strip().lower() for s in verdicts if s and s.strip()]
    sig = v.count("signal")
    noise = v.count("noise")
    unsure = v.count("unsure")
    return {
        "labeled": sig + noise + unsure,
        "signal": sig, "noise": noise, "unsure": unsure,
        "precision": fraction(sig, sig + noise),  # excludes unsure
    }


# ---------------------------------------------------------------- collectors

def _col(path: Path, name: str) -> list:
    if not path.exists() or path.stat().st_size == 0:
        return []
    t = pq.read_table(path, columns=[name]) if name in pq.read_schema(path).names \
        else None
    return t.column(name).to_pylist() if t is not None else []


def _latest_risk() -> Path | None:
    if not RISK_GLOB.exists():
        return None
    parts = sorted(RISK_GLOB.glob("dt=*/risk.parquet"))
    return parts[-1] if parts else None


def _payload_blobs_total() -> int:
    """Total distinct payloads (Parquet row-group metadata; no data scan)."""
    base = lib.PARQUET / "payload_blobs"
    if not base.exists():
        return 0
    try:
        import pyarrow.dataset as ds
        return ds.dataset(str(base), format="parquet").count_rows()
    except Exception:
        return 0


def gather_metrics() -> dict:
    m: dict = {"generated_at": None, "coverage": {}, "corpus": {}, "precision": None}

    evidence = _col(FINDINGS, "evidence_refs")
    m["corpus"]["findings_total"] = len(evidence)
    m["coverage"]["finding_evidence_coverage"] = nonempty_coverage(evidence)

    ai_what = _col(CONCLUSIONS, "ai_what")
    m["coverage"]["finding_narrative_coverage"] = nonempty_coverage(ai_what)

    # Deterministic verdicts (conclusions/verdict): share not unclassified.
    verdicts = _col(VERDICTS, "verdict")
    m["coverage"]["finding_verdict_coverage"] = fraction(
        sum(v != "unclassified" for v in verdicts), len(verdicts))

    risk = _latest_risk()
    tiers = _col(risk, "risk_tier") if risk else []
    m["corpus"]["ips_scored"] = len(tiers)
    m["coverage"]["risk_tier_coverage"] = nonempty_coverage(tiers)

    # Honest payload coverage: fraction of ALL distinct payloads explained by
    # trafficprint's reported clusters.  trafficprint excludes singletons
    # (HAVING count>=2) AND caps at the top ~50k clusters, so this is well
    # under 100% — the long tail + singletons are precisely the gap the
    # embedding-based pattern mining (Track B) aims to close.  Computing it
    # over trafficprint's own output alone would read ~100% and be meaningless.
    blob_counts = _col(TRAFFICPRINT, "blob_count")
    total_payloads = _payload_blobs_total()
    covered = sum(c for c in blob_counts if c)
    m["corpus"]["distinct_payloads"] = total_payloads
    m["corpus"]["payload_clusters_reported"] = len(blob_counts)
    m["coverage"]["payload_cluster_coverage"] = fraction(covered, total_payloads)

    techs = _col(ATTACKMAP, "technique")
    m["coverage"]["attack_technique_count"] = len(techs)

    # HTTP template coverage from the httppatterns stage (Track B). Honest
    # density-clustered fraction, not a nearest-centroid number.
    if HTTP_PATTERNS_SUMMARY.exists():
        s = json.loads(HTTP_PATTERNS_SUMMARY.read_text())
        # coverage is over the INTENT-BEARING HTTP subset (bare GET / excluded).
        m["coverage"]["http_intent_template_coverage"] = s.get("coverage_estimate")
        m["corpus"]["http_intent_templates"] = s.get("clusters", 0)
        m["corpus"]["http_novel_templates"] = s.get("novel_clusters", 0)

    # KG-lite finding fusion (Track C): how much the storyline graph collapses
    # the raw findings into operator-level campaigns.  Lower consolidation ratio
    # = more fusion; multi_finding_share = fraction of findings corroborated by
    # at least one sibling finding via a shared strong entity.
    if STORYLINES_SUMMARY.exists():
        s = json.loads(STORYLINES_SUMMARY.read_text())
        m["coverage"]["finding_consolidation_ratio"] = s.get("finding_consolidation_ratio")
        m["coverage"]["multi_finding_storyline_share"] = s.get("multi_finding_storyline_share")
        m["corpus"]["storylines_total"] = s.get("n_storylines", 0)
        m["corpus"]["storylines_multi_finding"] = s.get("n_multi_finding", 0)
        m["corpus"]["largest_storyline_findings"] = s.get("largest_storyline_findings", 0)

    if LABEL_DONE.exists():
        with open(LABEL_DONE, newline="") as f:
            rows = list(csv.DictReader(f))
        m["precision"] = precision_from_labels([r.get("verdict", "") for r in rows])

    return m


def export_label_queue(n: int) -> Path:
    """Write a real sample of findings for the operator to label."""
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    if not FINDINGS.exists():
        print("[bench] no findings.parquet to sample", file=sys.stderr)
        return LABEL_QUEUE
    cols = ["finding_id", "pattern_title", "severity", "src_ip_count"]
    have = pq.read_schema(FINDINGS).names
    cols = [c for c in cols if c in have]
    t = pq.read_table(FINDINGS, columns=cols).to_pylist()
    # highest-severity / largest first so the operator labels what matters
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    t.sort(key=lambda r: (sev_rank.get(str(r.get("severity")), 9),
                          -(r.get("src_ip_count") or 0)))
    with open(LABEL_QUEUE, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols + ["verdict", "note"])
        w.writeheader()
        for r in t[:n]:
            w.writerow({**r, "verdict": "", "note": ""})
    print(f"[bench] wrote {min(n, len(t))} findings -> {LABEL_QUEUE} "
          f"(mark verdict=signal|noise|unsure, save as {LABEL_DONE.name})",
          file=sys.stderr)
    return LABEL_QUEUE


def _render_md(m: dict) -> str:
    def pct(x):
        return "n/a" if x is None else f"{x*100:.1f}%"
    c = m["coverage"]
    lines = [
        "# Pipeline quantitative metrics",
        "",
        f"_Generated {m['generated_at']} UTC by bench/compute_metrics._",
        "",
        "## Corpus", "",
        "| quantity | value |", "| --- | --- |",
        f"| findings | {m['corpus'].get('findings_total', 0):,} |",
        f"| IPs scored | {m['corpus'].get('ips_scored', 0):,} |",
        f"| distinct payloads | {m['corpus'].get('distinct_payloads', 0):,} |",
        f"| payload clusters reported | {m['corpus'].get('payload_clusters_reported', 0):,} |",
        f"| storylines (multi-finding) | {m['corpus'].get('storylines_total', 0):,} "
        f"({m['corpus'].get('storylines_multi_finding', 0):,}) |",
        "",
        "## Coverage (label-free health signals)", "",
        "| metric | value |", "| --- | --- |",
        f"| finding_evidence_coverage | {pct(c.get('finding_evidence_coverage'))} |",
        f"| finding_narrative_coverage | {pct(c.get('finding_narrative_coverage'))} |",
        f"| risk_tier_coverage | {pct(c.get('risk_tier_coverage'))} |",
        f"| payload_cluster_coverage | {pct(c.get('payload_cluster_coverage'))} |",
        f"| http_intent_template_coverage | {pct(c.get('http_intent_template_coverage'))} |",
        f"| attack_technique_count | {c.get('attack_technique_count', 0)} |",
        f"| finding_consolidation_ratio | {c.get('finding_consolidation_ratio')} |",
        f"| multi_finding_storyline_share | {pct(c.get('multi_finding_storyline_share'))} |",
        "",
        "_`payload_cluster_coverage` = share of all distinct payloads explained "
        "by trafficprint's top non-singleton clusters; the remainder (singletons "
        "+ long tail) is the gap the embedding pattern-mining track targets._",
        "",
    ]
    if m.get("precision"):
        p = m["precision"]
        lines += [
            "## Operator-labeled precision", "",
            f"- labeled: **{p['labeled']}** (signal {p['signal']} / "
            f"noise {p['noise']} / unsure {p['unsure']})",
            f"- precision (excl. unsure): **{pct(p['precision'])}**", "",
        ]
    else:
        lines += [
            "## Operator-labeled precision", "",
            "_No labels yet. Run `python src/bench/compute_metrics.py "
            "--export-labels 50`, mark `verdict`, save as "
            "`output/eval/label_queue_labeled.csv`, and re-run._", "",
        ]
    return "\n".join(lines) + "\n"


def write_metrics(m: dict) -> dict[str, Path]:
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    date = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    m["generated_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    json_path = EVAL_DIR / f"metrics_{date}.json"
    json_path.write_text(json.dumps(m, indent=2))
    md_path = EVAL_DIR / "metrics.md"
    md_path.write_text(_render_md(m))
    return {"json": json_path, "markdown": md_path}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export-labels", type=int, metavar="N",
                    help="Write N findings to output/eval/label_queue.csv for "
                         "operator labeling, then exit.")
    args = ap.parse_args()

    if args.export_labels:
        export_label_queue(args.export_labels)
        return 0

    m = gather_metrics()
    paths = write_metrics(m)
    print(f"[bench] wrote {paths['json']}")
    print(f"[bench] wrote {paths['markdown']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

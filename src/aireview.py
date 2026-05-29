#!/usr/bin/env python3
"""
aireview - multi-AI cross-review of the SensorGrind tool, its analyses,
and its comprehensive report.

For each of five review TOPICS we build a structured prompt with the
relevant context (code summary, analyzer outputs, report sections),
and send the same prompt to every AI provider for which we have both a
key file AND the SDK installed.  Responses are cached per
(topic, provider, model, prompt-sha256) and aggregated into a
side-by-side review document.

Topics
------
  arch       Architecture / engineering review
  methods    Analytical methodology review
  findings   Threat-finding accuracy & attribution review
  report     Report quality, clarity, and defender utility review
  gaps       Blind-spot identification - what is the tool NOT catching?

Output
------
  output/reports/aireview/aireview.md
  output/reports/aireview/per_provider.parquet
  output/ai_cache/aireview_{provider}_{model}_{topic}_{sha}.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib
import json
import os
import sys
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib
import aipayloaddecode as aid


OUT_DIR = lib.REPORTS / "aireview"
CACHE = lib.OUTPUT_DIR / "ai_cache"


def _file_excerpt(path: Path, max_chars: int) -> str:
    if not path.exists():
        return f"(file missing: {path.relative_to(lib.REPO_ROOT)})"
    text = path.read_text(errors="replace")
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + f"\n\n... [{len(text) - max_chars:,} chars elided] ...\n\n" + text[-half:]


def _code_tree() -> str:
    """Concise list of src/ files with line counts."""
    lines = ["src/ tree (file:lines):"]
    for p in sorted(Path("src").rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        try:
            n = sum(1 for _ in p.open())
        except Exception:
            n = 0
        lines.append(f"  {p}: {n} lines")
    return "\n".join(lines)


def _build_prompts() -> dict[str, str]:
    REPORTS = lib.REPORTS

    arch = f"""You are a senior threat-intelligence platform architect reviewing the
SensorGrind_AI honeypot-analysis tool.  Below are: (a) the source tree, (b)
the v2 orchestrator with its full pipeline stage list, and (c) the shared
library that all analyzers use.  Read them and produce a critical
architecture review.

{_code_tree()}

=== src/evolve.py (orchestrator) ===
{_file_excerpt(Path("src/evolve.py"), 8000)}

=== src/sg/lib.py (shared library) ===
{_file_excerpt(Path("src/sg/lib.py"), 12000)}

=== src/sg/features.py (feature store) ===
{_file_excerpt(Path("src/sg/features.py"), 4000)}

=== src/sg/models.py (model registry) ===
{_file_excerpt(Path("src/sg/models.py"), 4000)}

Return STRICT JSON with these keys (no markdown fences, no prose outside JSON):

  overall_grade           one of "A", "B", "C", "D", "F"
  strengths               array of 3-6 short strings (1 sentence each)
  weaknesses              array of 3-6 short strings (1 sentence each)
  scalability_risks       array of strings naming specific bottlenecks
  design_recommendations  array of strings, concrete improvements with code-level specificity
  one_paragraph_summary   string

Return ONLY the JSON object."""

    methods = f"""You are reviewing the analytical METHODOLOGY of the SensorGrind_AI
tool.  Below are excerpts of every analyzer module - read the techniques
they use (FP-Growth, HDBSCAN, ECOD, KS-test, Louvain, PELT, etc.) and
critique their appropriateness for honeypot data.

{_file_excerpt(Path("src/benignfilter.py"), 4000)}

{_file_excerpt(Path("src/models/train_threat_classifier.py"), 4000)}

{_file_excerpt(Path("src/models/train_actor_clusterer.py"), 4000)}

{_file_excerpt(Path("src/models/detect_drift.py"), 4000)}

{_file_excerpt(Path("src/mining/mine_itemsets.py"), 4000)}

{_file_excerpt(Path("src/mining/promote_patterns.py"), 4000)}

{_file_excerpt(Path("src/longitudinal/detect_changepoints.py"), 3000)}

{_file_excerpt(Path("src/longitudinal/detect_coordination.py"), 3000)}

{_file_excerpt(Path("src/longitudinal/cross_modal_lag.py"), 3000)}

{_file_excerpt(Path("src/actorlink.py"), 5000)}

{_file_excerpt(Path("src/asnintel.py"), 4000)}

Return STRICT JSON:

  overall_grade               "A"-"F"
  technique_assessment        array of objects: each {{"technique": "...", "module": "...", "appropriate_for_data": true/false, "comment": "..."}}
  statistical_concerns        array of strings naming specific stat-rigor issues (sample-size assumptions, multiple-test correction, false-positive rates, etc.)
  bias_risks                  array of strings naming where the methodology could mis-classify
  recommended_improvements    array of strings with concrete next-step techniques (cite paper titles or library names where useful)
  one_paragraph_summary       string

Return ONLY the JSON object."""

    findings = f"""You are an experienced SOC analyst / threat hunter reviewing the
THREAT FINDINGS produced by the SensorGrind_AI tool over 6.6 years of
honeypot data (1.1 billion packets).  Below is the actor-atlas output
(actorlink + originintel LLM profiles) and the per-ASN threat profile
(asnintel).  Critically assess: are these findings plausible, are the
attributions well-supported, and what would you change before acting on
them in production?

=== output/reports/originintel/originintel.md ===
{_file_excerpt(REPORTS / "originintel" / "originintel.md", 25000)}

=== output/reports/asnintel/asnintel.md (top section) ===
{_file_excerpt(REPORTS / "asnintel" / "asnintel.md", 8000)}

=== output/reports/cidrintel/cidrintel.md (top section) ===
{_file_excerpt(REPORTS / "cidrintel" / "cidrintel.md", 5000)}

Return STRICT JSON:

  overall_credibility         "high" | "medium" | "low"
  findings_well_supported     array of community/finding IDs you think are well attributed
  findings_questionable       array of objects: each {{"id": "...", "concern": "..."}}
  attribution_risks           array of strings naming attribution failure modes
  false_positive_examples     array of strings with specific cases that may be benign mis-classified as hostile
  defender_action_concerns    array of strings naming over- or under-reactive defender recommendations
  one_paragraph_summary       string

Return ONLY the JSON object."""

    report = f"""You are a senior SOC director receiving the SensorGrind_AI
comprehensive report.  Critically review it for clarity, actionability,
completeness, and prioritization - would a SOC team actually be able to
use this to make decisions?

=== output/reports/COMPREHENSIVE.md (full) ===
{_file_excerpt(REPORTS / "COMPREHENSIVE.md", 60000)}

Return STRICT JSON:

  overall_grade              "A"-"F"
  clarity_score              integer 1-10
  actionability_score        integer 1-10
  prioritization_score       integer 1-10
  best_sections              array of section numbers/names that are most useful
  weakest_sections           array of section numbers/names with the reason
  missing_content            array of strings naming what defenders need that's not in this report
  formatting_issues          array of strings (tables too wide, missing context, awkward narrative, etc.)
  improvements_recommended   array of strings with concrete report-edit suggestions
  one_paragraph_summary      string

Return ONLY the JSON object."""

    gaps = f"""You are red-teaming the SensorGrind_AI tool itself.  Given the
analyses below, what is the tool MISSING - patterns, anomalies, attacker
techniques, or attribution opportunities that a sophisticated adversary
could exploit because the tool doesn't see them?

{_code_tree()}

=== src/sgquery.py + src/evolve.py (pipeline overview) ===
{_file_excerpt(Path("src/sgquery.py"), 3000)}
{_file_excerpt(Path("src/evolve.py"), 5000)}

=== analyzer outputs index ===
{_file_excerpt(REPORTS / "COMPREHENSIVE.md", 30000)}

Return STRICT JSON:

  detection_blind_spots      array of strings naming specific attack patterns the tool cannot see
  attribution_blind_spots    array of strings naming attribution opportunities being missed
  evasion_opportunities      array of strings naming how an adversary could fly under the tool's radar
  data_quality_concerns      array of strings naming sources of bias/error in the inputs
  missing_signals            array of strings naming useful signals that aren't being computed
  priority_additions         array of objects: each {{"module": "...", "why": "...", "impact": "high|medium|low"}}
  one_paragraph_summary      string

Return ONLY the JSON object."""

    return {
        "arch": arch,
        "methods": methods,
        "findings": findings,
        "report": report,
        "gaps": gaps,
    }


RESULT_SCHEMA = pa.schema([
    ("topic",       pa.string()),
    ("provider",    pa.string()),
    ("model",       pa.string()),
    ("status",      pa.string()),   # "ok" | "skipped" | "failed"
    ("response_json", pa.string()),
    ("reviewed_at", pa.timestamp("us", tz="UTC")),
])


def _cache_path(topic: str, provider: str, model: str, prompt_sha: str) -> Path:
    safe_model = model.replace("/", "_").replace(":", "_")
    return CACHE / f"aireview_{provider}_{safe_model}_{topic}_{prompt_sha}.json"


def _all_providers(prefer: list[str] | None = None) -> list[tuple[dict, str]]:
    """Auto-discover all providers with usable (key, SDK) pairs."""
    out = []
    seen = set()
    for p in aid.PROVIDERS:
        if prefer and p["name"] not in prefer:
            continue
        if p["name"] in seen:
            continue
        key_file = lib.REPO_ROOT / p["key_file"]
        if not key_file.exists():
            continue
        try:
            importlib.import_module(p["sdk"])
        except ImportError:
            print(f"[aireview] {p['name']}: SDK not installed ({p['sdk']}), skipping",
                  file=sys.stderr)
            continue
        try:
            key = key_file.read_text().strip()
        except Exception:
            continue
        if not key or key.startswith("#"):
            continue
        out.append((p, key))
        seen.add(p["name"])
    return out


def _safe_call(provider: dict, api_key: str, model: str, prompt: str,
               retries: int = 1, retry_sleep: float = 5.0) -> dict | None:
    last = None
    for attempt in range(retries + 1):
        try:
            return provider["call"](api_key, model, prompt)
        except Exception as e:
            last = e
            if attempt < retries:
                print(f"[aireview]   {provider['name']} call failed: {e}; "
                      f"retry in {retry_sleep:.1f}s", file=sys.stderr)
                time.sleep(retry_sleep)
            else:
                print(f"[aireview]   {provider['name']} call failed: {e}",
                      file=sys.stderr)
    return None


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    providers = _all_providers(args.providers)
    if not providers:
        print("[aireview] no AI provider available "
              "(no '*.key.txt' file paired with an installed SDK).  "
              "Skipping multi-AI review.  This is fine - rest of "
              "pipeline does not depend on it.", file=sys.stderr)
        return 0
    print(f"[aireview] providers active: "
          f"{', '.join(p['name'] for p, _ in providers)}", file=sys.stderr)

    prompts = _build_prompts()
    topics = args.topics or list(prompts.keys())
    print(f"[aireview] topics: {topics}", file=sys.stderr)

    out_rows: list[dict] = []

    for topic in topics:
        prompt = prompts[topic]
        prompt_sha = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        for provider, key in providers:
            model = (args.model_override.get(provider["name"], None)
                     if args.model_override else None) or provider["default_model"]
            cache_p = _cache_path(topic, provider["name"], model, prompt_sha)
            if cache_p.exists() and not args.force:
                parsed = json.loads(cache_p.read_text())
                print(f"[aireview] cache hit: {topic} / {provider['name']}",
                      file=sys.stderr)
                status = "ok"
            else:
                print(f"[aireview] {topic} -> {provider['name']}/{model} "
                      f"(prompt {len(prompt):,} chars)...", file=sys.stderr)
                parsed = _safe_call(provider, key, model, prompt,
                                    retries=1, retry_sleep=args.sleep)
                if parsed is None:
                    out_rows.append({
                        "topic": topic, "provider": provider["name"],
                        "model": model, "status": "failed",
                        "response_json": "",
                        "reviewed_at": _dt.datetime.now(_dt.timezone.utc),
                    })
                    continue
                cache_p.write_text(json.dumps(parsed, indent=2))
                status = "ok"
                time.sleep(args.sleep)
            out_rows.append({
                "topic": topic, "provider": provider["name"],
                "model": model, "status": status,
                "response_json": json.dumps(parsed, separators=(",", ":")),
                "reviewed_at": _dt.datetime.now(_dt.timezone.utc),
            })

    pq.write_table(pa.Table.from_pylist(out_rows, schema=RESULT_SCHEMA),
                   OUT_DIR / "per_provider.parquet",
                   compression="zstd", compression_level=3)

    # ---- aggregate markdown ----
    md = ["# aireview - multi-AI cross-review of SensorGrind_AI", "",
          f"_Providers consulted: "
          f"{', '.join(p['name'] for p, _ in providers)}_  ",
          f"_Topics reviewed: {', '.join(topics)}_  ",
          f"_Generated: {_dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}_",
          "",
          "Each topic has one section per provider, plus a consensus "
          "summary listing items multiple providers agreed on.", ""]

    rows_by_topic: dict[str, list[dict]] = {}
    for r in out_rows:
        rows_by_topic.setdefault(r["topic"], []).append(r)

    topic_titles = {
        "arch":     "1. Architecture / Engineering Review",
        "methods":  "2. Analytical Methodology Review",
        "findings": "3. Threat-Finding Accuracy & Attribution Review",
        "report":   "4. Report Quality & Defender Utility Review",
        "gaps":     "5. Blind-Spot / Red-Team Review",
    }

    for topic in topics:
        title = topic_titles.get(topic, topic)
        md.append(f"## {title}")
        md.append("")
        rows = rows_by_topic.get(topic, [])
        for r in rows:
            md.append(f"### {r['provider']} ({r['model']})")
            md.append("")
            if r["status"] != "ok" or not r["response_json"]:
                md.append("_(call failed or empty response)_")
                md.append("")
                continue
            try:
                obj = json.loads(r["response_json"])
            except Exception:
                md.append("_(unparseable response)_")
                md.append("")
                continue
            for k, v in obj.items():
                if isinstance(v, list):
                    md.append(f"**{k}:**")
                    md.append("")
                    for item in v:
                        if isinstance(item, dict):
                            sub = "; ".join(f"{kk}={vv}" for kk, vv in item.items())
                            md.append(f"- {sub}")
                        else:
                            md.append(f"- {item}")
                    md.append("")
                else:
                    md.append(f"**{k}:** {v}")
                    md.append("")

        # consensus across providers - extract via a separate LLM call so
        # that semantically-equivalent points raised in different language
        # are counted as agreement, not as disagreement.
        md.append(f"### Consensus across providers ({topic})")
        md.append("")
        all_objs: list[dict] = []
        for r in rows:
            if r["status"] != "ok":
                continue
            try:
                all_objs.append(json.loads(r["response_json"]))
            except Exception:
                continue
        if len(all_objs) < 2:
            md.append("_(too few providers responded to compute consensus)_")
            md.append("")
            continue

        # Build a compact corpus of each provider's bullet-points so the
        # synthesizer can score agreement / divergence.
        corpus_lines = []
        for i, obj in enumerate(all_objs):
            provider_name = [p for p, _ in providers
                             if any(rr['provider'] == p['name']
                                    and rr['status'] == 'ok'
                                    and rr.get('topic') == topic
                                    and json.loads(rr['response_json']) == obj
                                    for rr in rows)]
            label = provider_name[0]["name"] if provider_name else f"reviewer_{i}"
            corpus_lines.append(f"--- {label} ---")
            for k, v in obj.items():
                if isinstance(v, list):
                    for item in v:
                        s = item if isinstance(item, str) else json.dumps(item, default=str)
                        corpus_lines.append(f"  [{k}] {s}")
                else:
                    corpus_lines.append(f"  [{k}] {v}")
        corpus = "\n".join(corpus_lines)

        synth_prompt = f"""Below are {len(all_objs)} separate reviewers' responses
on the same topic.  Each bullet is tagged with the reviewer's name and
the field of their structured response it came from.  Identify themes
that two or more reviewers raised independently (paraphrasing each other
counts; verbatim isn't required), and tabulate them.

{corpus}

Respond in strict JSON (no fences):

  consensus_themes      array of objects; each {{"theme": "...", "raised_by": ["provider1", "provider2", ...], "field": "weaknesses|recommendations|...", "summary": "1-2 sentence consolidation of what all those reviewers were saying"}}
  unique_per_provider   object mapping provider-name -> array of strings: their points NOT echoed by any other reviewer
  consensus_grade       if reviewers gave grades, the median/mode grade
  one_paragraph_summary string

Return ONLY the JSON object."""
        # Use the first available provider (cheapest path) for synthesis.
        synth_provider, synth_key = providers[0]
        synth_model = synth_provider["default_model"]
        synth_sha = hashlib.sha256(synth_prompt.encode()).hexdigest()[:16]
        synth_cache = _cache_path(f"{topic}_synth", synth_provider["name"],
                                  synth_model, synth_sha)
        if synth_cache.exists() and not args.force:
            synth = json.loads(synth_cache.read_text())
        else:
            print(f"[aireview]   synthesizing {topic} consensus via "
                  f"{synth_provider['name']}/{synth_model}...", file=sys.stderr)
            synth = _safe_call(synth_provider, synth_key, synth_model,
                               synth_prompt, retries=1,
                               retry_sleep=args.sleep)
            if synth is not None:
                synth_cache.write_text(json.dumps(synth, indent=2))
                time.sleep(args.sleep)
        if not synth:
            md.append("_(consensus synthesis failed)_")
            md.append("")
            continue
        if "consensus_grade" in synth:
            md.append(f"**Consensus grade:** {synth['consensus_grade']}")
            md.append("")
        if "one_paragraph_summary" in synth:
            md.append(synth["one_paragraph_summary"])
            md.append("")
        themes = synth.get("consensus_themes", [])
        if themes:
            md.append(f"**Shared themes raised by multiple providers:**")
            md.append("")
            for t in themes:
                raised_by = t.get("raised_by", [])
                field = t.get("field", "")
                summary = t.get("summary", "")
                theme = t.get("theme", "")
                md.append(f"- **{theme}** _(field: {field}; raised by: "
                          f"{', '.join(raised_by)})_  ")
                md.append(f"  {summary}")
            md.append("")
        unique = synth.get("unique_per_provider", {})
        if isinstance(unique, dict) and any(unique.values()):
            md.append("**Unique observations (raised by only one provider):**")
            md.append("")
            for prov, items in unique.items():
                if not items:
                    continue
                md.append(f"_{prov}:_")
                for it in items[:8]:
                    md.append(f"  - {it}")
                md.append("")

    (OUT_DIR / "aireview.md").write_text("\n".join(md) + "\n")
    print(f"[aireview] wrote {OUT_DIR}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--providers", nargs="*", default=None,
                    help="Subset of providers to use; default: all available")
    ap.add_argument("--topics", nargs="*", default=None,
                    help="Subset of topics: arch, methods, findings, report, gaps")
    ap.add_argument("--force", action="store_true",
                    help="Re-call API even for cached results")
    ap.add_argument("--sleep", type=float, default=0.6)
    ap.add_argument("--model-override", default=None,
                    help="JSON map of provider->model overrides "
                         "(e.g. '{\"openai\":\"gpt-4o-mini\"}')")
    args = ap.parse_args()
    if args.model_override:
        try:
            args.model_override = json.loads(args.model_override)
        except Exception:
            print("[aireview] bad --model-override JSON; ignoring",
                  file=sys.stderr)
            args.model_override = None
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
bench/ai_threat_analysis — fan the COMPREHENSIVE report out to several LLMs as
senior threat analysts, then synthesize their analyses.

This is NOT the self-review (aireview, which critiques the *tool*). This asks
each model to reason about the *adversaries* the report describes: subtle
patterns, cross-finding linkage, actor motivations / intent, campaign
objectives, operator tradecraft, and likely next moves — advanced analysis, not
a summary.

Reuses the provider key files + SDKs from aipayloaddecode (claude/openai/xai/
mistral/gemini), but with free-form markdown output and full token budgets
(the shared provider.call forces short JSON, which would gut the analysis).

Each provider's analysis is cached by (provider, model, sha256(prompt)). A final
synthesis pass (default: claude) consolidates them, adjudicating agreement vs
divergence and surfacing each model's best non-obvious insight.

Output: output/reports/ai_threat_analysis/analysis.md (synthesis + per-model
appendix) and per_provider.parquet.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib
import sys
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib
import aipayloaddecode as aid

OUT_DIR = lib.REPORTS / "ai_threat_analysis"
CACHE = lib.OUTPUT_DIR / "ai_cache"
REPORT = lib.REPORTS / "COMPREHENSIVE.md"
MAX_TOKENS = 16000

# Sections worth an analyst's attention (in report order); appendices/boilerplate
# dropped. Header substrings, lowercased.
PRIORITY = [
    "tl;dr", "cross-signal", "executive", "risk stratification",
    "attack chain", "coordinated activity", "pattern & rule",
    "botnet & malware", "exploit probes", "operator clustering",
    "survival & persistence", "hostile asns", "compromised cidr",
    "attacker tooling", "actor atlas", "landscape evolution",
    "protocol state-machine", "non-tcp", "packet choreography",
    "fingerprint rotation", "campaign migration", "att&ck",
    "http request templates", "payload byte-level",
]
EVIDENCE_BUDGET = 115_000  # chars total; keeps gpt-4o/mistral 128k-ctx in play
PER_SECTION = 7_000        # head-cap per section so no single one (e.g. the huge
                           # cross-signal narrative) crowds out the rest

ANALYST_PROMPT = """You are a senior cyber threat-intelligence analyst (15+ years: \
APT tracking, botnet takedowns, CTI fusion). Below is the analytic report from a \
long-window (662 active days, 1.1B events) ULTRA-LOW-INTERACTION honeypot sensor \
(stateless-TCP design — it never completes app-layer conversations, so most \
attacker interactions are a single opening probe).

Do NOT summarize the report. Produce ADVANCED ANALYSIS of the ADVERSARIES it \
describes. Reason past what is stated to what it IMPLIES. Specifically:
- Subtle / non-obvious patterns and what they reveal.
- Actor MOTIVATIONS and INTENT — what is each actor/campaign actually trying to \
achieve (recon, staging, monetization, disruption, espionage)? Targeted vs \
opportunistic?
- Cross-finding linkage: which findings are plausibly the same operator/toolkit/\
campaign even when the report lists them separately? Infrastructure & operator \
relationships.
- Operator TRADECRAFT: tooling maturity, automation, OPSEC, evasion, rotation, \
timing/cadence tells.
- Strategic/economic drivers and likely NEXT MOVES.
- Where the report's own conclusions are likely OVER- or UNDER-stated, and what \
it is probably MISSING given the sensor's blind spots.

Be concrete and cite the report's evidence. Rate each major judgment confidence \
High/Medium/Low and state the assumption it rests on.

Return well-structured markdown with these sections:
## Headline judgments
## Subtle patterns & what they imply
## Actor motivations & intent
## Campaign & infrastructure linkage
## Tradecraft & tooling inferences
## Where the report is over/under-stated or blind
## Highest-value follow-ups

=== HONEYPOT REPORT (curated high-signal sections) ===
"""

SYNTH_PROMPT = """You are the lead threat-intelligence analyst. {n} peer analysts \
(different AI models) independently analyzed the SAME ultra-low-interaction \
honeypot report. Their analyses are below, labeled by model.

Produce ONE consolidated ADVANCED-ANALYSIS brief. Do not merely concatenate:
- State the strongest CONSENSUS judgments (multiple analysts agree) and mark them \
high-confidence.
- Surface where analysts DIVERGE and adjudicate — say who is more likely right and \
why.
- Extract the single best NON-OBVIOUS insight unique to each analyst (attribute it).
- Add your OWN meta-observations the others missed or under-weighted.
- Keep confidence ratings (H/M/L) and the assumptions behind them.

Same section structure as the analysts:
## Headline judgments (consensus, with confidence)
## Subtle patterns & what they imply
## Actor motivations & intent
## Campaign & infrastructure linkage
## Tradecraft & tooling inferences
## Disagreements & adjudication
## Best unique insight per analyst
## Where the report is likely blind
## Highest-value follow-ups

=== PEER ANALYSES ===
"""


def build_evidence() -> str:
    """Curate high-signal report sections up to EVIDENCE_BUDGET chars."""
    text = REPORT.read_text(errors="replace")
    lines = text.splitlines(keepends=True)
    # split into (header, body) sections on '## '
    sections, cur_h, cur = [], "(preamble)", []
    for ln in lines:
        if ln.startswith("## "):
            sections.append((cur_h, "".join(cur)))
            cur_h, cur = ln.strip(), [ln]
        else:
            cur.append(ln)
    sections.append((cur_h, "".join(cur)))

    out, used = [], 0
    for h, body in sections:
        hl = h.lower()
        if not (h == "(preamble)" or any(k in hl for k in PRIORITY)):
            continue
        if "appendix" in hl or "glossary" in hl:
            continue
        # head-cap each section so one verbose section can't dominate the pack
        if len(body) > PER_SECTION:
            body = body[:PER_SECTION] + "\n... [section truncated]\n\n"
        if used + len(body) > EVIDENCE_BUDGET:
            break
        out.append(body)
        used += len(body)
    return "".join(out)


# ---- per-SDK free-form calls (markdown, full token budget) ------------------

def _call(provider_name: str, api_key: str, model: str, prompt: str) -> str:
    if provider_name == "claude":
        import anthropic
        c = anthropic.Anthropic(api_key=api_key, timeout=600.0)
        r = c.messages.create(model=model, max_tokens=MAX_TOKENS,
                              messages=[{"role": "user", "content": prompt}])
        return "".join(b.text for b in r.content if hasattr(b, "text"))
    if provider_name in ("openai", "xai"):
        import openai
        kw = {"base_url": "https://api.x.ai/v1"} if provider_name == "xai" else {}
        c = openai.OpenAI(api_key=api_key, timeout=600.0, **kw)
        r = c.chat.completions.create(model=model, max_tokens=MAX_TOKENS,
                                      messages=[{"role": "user", "content": prompt}])
        return r.choices[0].message.content or ""
    if provider_name == "mistral":
        from mistralai.client.sdk import Mistral
        c = Mistral(api_key=api_key, timeout_ms=600_000)
        r = c.chat.complete(model=model, max_tokens=MAX_TOKENS,
                            messages=[{"role": "user", "content": prompt}])
        return r.choices[0].message.content or ""
    if provider_name == "gemini":
        from google import genai
        c = genai.Client(api_key=api_key)
        r = c.models.generate_content(model=model, contents=prompt)
        return r.text or ""
    raise ValueError(f"unknown provider {provider_name}")


def _providers(prefer: list[str] | None):
    out = []
    for p in aid.PROVIDERS:
        if prefer and p["name"] not in prefer:
            continue
        kf = lib.REPO_ROOT / p["key_file"]
        if not kf.exists():
            continue
        try:
            importlib.import_module(p["sdk"])
        except ImportError:
            print(f"[ai-threat] {p['name']}: SDK missing, skip", file=sys.stderr)
            continue
        key = kf.read_text().strip()
        if key and not key.startswith("#"):
            out.append((p, key))
    return out


def _cached(provider: str, model: str, sha: str) -> Path:
    return CACHE / f"threatanalysis_{provider}_{model}_{sha}.md"


def run(args) -> int:
    if not REPORT.exists():
        print(f"[ai-threat] {REPORT} missing — run the report stage first",
              file=sys.stderr)
        return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    providers = _providers(args.providers)
    if not providers:
        print("[ai-threat] no usable AI provider (key + SDK)", file=sys.stderr)
        return 2
    print(f"[ai-threat] analysts: {', '.join(p['name'] for p, _ in providers)}",
          file=sys.stderr)

    evidence = build_evidence()
    prompt = ANALYST_PROMPT + evidence
    sha = hashlib.sha256(prompt.encode()).hexdigest()[:16]
    print(f"[ai-threat] evidence pack {len(evidence):,} chars "
          f"(prompt sha {sha})", file=sys.stderr)

    analyses: list[tuple[str, str, str]] = []  # (provider, model, text)
    rows = []
    for p, key in providers:
        model = p["default_model"]
        cp = _cached(p["name"], model, sha)
        if cp.exists() and not args.force:
            text = cp.read_text()
            print(f"[ai-threat] cache hit: {p['name']}", file=sys.stderr)
        else:
            print(f"[ai-threat] {p['name']}/{model} analyzing...", file=sys.stderr)
            try:
                text = _call(p["name"], key, model, prompt)
            except Exception as e:
                print(f"[ai-threat]   {p['name']} failed: {e}", file=sys.stderr)
                rows.append({"provider": p["name"], "model": model,
                             "status": "failed", "chars": 0})
                continue
            cp.write_text(text)
            time.sleep(args.sleep)
        analyses.append((p["name"], model, text))
        rows.append({"provider": p["name"], "model": model,
                     "status": "ok", "chars": len(text)})

    if not analyses:
        print("[ai-threat] all providers failed", file=sys.stderr)
        return 1

    # ---- synthesis ----
    synth_text = ""
    synth_provider = next((pk for pk in providers
                           if pk[0]["name"] == args.synth), None) or providers[0]
    sp, skey = synth_provider
    joined = "\n\n".join(f"### Analyst: {name} ({model})\n\n{text}"
                         for name, model, text in analyses)
    synth_prompt = SYNTH_PROMPT.format(n=len(analyses)) + joined
    ssha = hashlib.sha256(synth_prompt.encode()).hexdigest()[:16]
    scp = _cached(f"SYNTH_{sp['name']}", sp["default_model"], ssha)
    if scp.exists() and not args.force:
        synth_text = scp.read_text()
        print("[ai-threat] synthesis cache hit", file=sys.stderr)
    else:
        print(f"[ai-threat] synthesizing with {sp['name']}...", file=sys.stderr)
        try:
            synth_text = _call(sp["name"], skey, sp["default_model"], synth_prompt)
            scp.write_text(synth_text)
        except Exception as e:
            print(f"[ai-threat] synthesis failed: {e}", file=sys.stderr)
            synth_text = "_(synthesis failed; see per-analyst sections below)_"

    ts = _dt.datetime.now(_dt.timezone.utc).isoformat()
    md = [
        "# Multi-AI Threat Analysis of the SensorGrind Honeypot Report",
        "",
        f"_Generated {ts} UTC. Analysts: "
        f"{', '.join(f'{n} ({m})' for n, m, _ in analyses)}. "
        f"Synthesis: {sp['name']} ({sp['default_model']})._",
        "",
        "> Independent advanced analysis of the adversaries described in "
        "`COMPREHENSIVE.md` — actor intent, campaign linkage, tradecraft. Each "
        "model saw the same curated high-signal evidence pack.",
        "",
        "---", "", "# Consolidated Synthesis", "", synth_text, "",
        "---", "", "# Per-analyst analyses", "",
    ]
    for name, model, text in analyses:
        md += [f"## {name} ({model})", "", text, "", "---", ""]
    (OUT_DIR / "analysis.md").write_text("\n".join(md))
    pq.write_table(pa.Table.from_pylist(rows), OUT_DIR / "per_provider.parquet",
                   compression="zstd", compression_level=3)
    print(f"[ai-threat] wrote {OUT_DIR / 'analysis.md'} "
          f"({len(analyses)} analysts + synthesis)", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--providers", nargs="*", help="subset of provider names")
    ap.add_argument("--synth", default="claude", help="provider for synthesis")
    ap.add_argument("--force", action="store_true", help="ignore cache")
    ap.add_argument("--sleep", type=float, default=2.0)
    return run(ap.parse_args())


if __name__ == "__main__":
    sys.exit(main())

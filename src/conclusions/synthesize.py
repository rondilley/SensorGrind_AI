#!/usr/bin/env python3
"""
conclusions/synthesize - LLM-written conclusion narratives for each finding.

Reads `output/conclusions/findings.parquet` (produced by correlate.py)
and for each finding asks the configured LLM to write a structured
conclusion: what / why-it-is-noteworthy / threat-model / risk-if-realized
/ recommended-action.  Caches every response by sha256 of the prompt so
re-runs are free unless --force.

Provider auto-discovery mirrors `aipayloaddecode.py` (anthropic, openai,
xai, mistral, gemini - first key+SDK combination wins).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sg import lib
import aipayloaddecode as aipd


OUT_DIR = lib.OUTPUT_DIR / "conclusions"
STORY_DIR = OUT_DIR / "storylines"
CACHE = lib.OUTPUT_DIR / "ai_cache"


CONCLUSION_SCHEMA = pa.schema([
    ("finding_id",        pa.string()),
    ("pattern_id",        pa.string()),
    ("pattern_title",     pa.string()),
    ("severity",          pa.string()),
    ("category",          pa.string()),
    ("src_ip_count",      pa.uint32()),
    ("src_ips_sample",    pa.string()),
    ("asns_sample",       pa.string()),
    ("countries_sample",  pa.string()),
    ("key_metrics",       pa.string()),
    ("evidence_refs",     pa.string()),
    ("report_anchor",     pa.string()),
    ("first_seen",        pa.string()),
    ("last_seen",         pa.string()),
    ("provider",          pa.string()),
    ("model",             pa.string()),
    ("ai_title",          pa.string()),
    ("ai_what",           pa.string()),
    ("ai_why_noteworthy", pa.string()),
    ("ai_threat_model",   pa.string()),
    ("ai_risk_if_realized", pa.string()),
    ("ai_recommended_action", pa.string()),
    ("ai_confidence",     pa.string()),
    ("synthesized_at",    pa.timestamp("us", tz="UTC")),
])


# The sensor context is critical: a honeypot at 10.10.10.40 receives
# ONLY unsolicited inbound traffic.  Any "answer-style" packet (SCTP
# INIT, OSPF Hello, etc.) is by definition not a response to anything we
# sent - it is recon or an active intrusion attempt.  We pass this to
# the LLM so its conclusions are framed for an unsolicited-inbound
# threat model rather than a generic network.
SENSOR_CONTEXT = """\
The sensor is an unsolicited-inbound honeypot at IP 10.10.10.40 -
nothing legitimate ever initiates a session with it.  Every packet
captured is either (a) opportunistic recon/scan against the wider
internet that happened to land here, (b) a targeted probe, or (c) an
exploit attempt.  Because we never *send* anything, no legitimate
return traffic exists - so things like SCTP arrivals, OSPF Hellos,
mid-stream TCP payloads, or banner echoes are all anomalous on their
face.  Frame your analysis from a defender's perspective: what does the
combination of signals tell us, and what would a defender at a real
service-provider see if this attacker turned the same toolkit on their
production estate?"""


PROMPT_TEMPLATE = """You are a senior threat-intel analyst.  Write a structured conclusion for one cross-signal finding from a long-running internet honeypot.

# Sensor context

{sensor_context}

# The finding

- pattern_id: `{pattern_id}`
- title:      {pattern_title}
- severity:   {severity}
- category:   {category}
- distinct source IPs in the finding: {src_ip_count}
- representative source IPs: {src_ips}
- ASNs:      {asns}
- countries: {countries}
- first observed: {first_seen}
- last observed:  {last_seen}

# Cross-analyzer evidence references

{evidence_refs}

# Raw metrics (machine-extracted)

```json
{key_metrics}
```

# Your task

Explain to a defender what this pattern *means* and why it matters.  Be specific - reference the metrics above when relevant.  Do NOT just restate the title.  Do NOT use phrases like "this is noteworthy" without saying *why*.  Spell out the attacker's likely goal, the real-world attack this matches (named TTP if applicable), and the consequence if the same toolkit were turned on a production service.

Reply with strict JSON (no markdown fences, no prose outside the JSON):

  ai_title              short punchy title (max ~80 chars) suitable as a report heading
  ai_what               1-2 sentence plain-English description of what happened
  ai_why_noteworthy     2-4 sentences explaining why this combination of signals is anomalous AND dangerous; cite specific numbers from the metrics
  ai_threat_model       which real-world attack technique this matches (named where possible: SS7 location-tracking, Diameter signaling injection, GTP roaming abuse, IoT botnet C2 rotation, credential-spray, slowloris, etc.)
  ai_risk_if_realized   2-3 sentences on the consequence at a real target (what gets stolen / disrupted / billed-against / impersonated)
  ai_recommended_action 2-4 short bullets a defender can act on this week (block, detect, hunt, log).  Each bullet a string in a JSON array.
  ai_confidence         "high" | "medium" | "low" - how confident you are that this is a real threat vs noise

Return ONLY the JSON object."""


def _prompt(f: dict) -> str:
    return PROMPT_TEMPLATE.format(
        sensor_context=SENSOR_CONTEXT,
        pattern_id=f["pattern_id"],
        pattern_title=f["pattern_title"],
        severity=f["severity"],
        category=f["category"],
        src_ip_count=f["src_ip_count"],
        src_ips=f["src_ips_sample"] or "(no per-IP sample - finding is aggregate)",
        asns=f["asns_sample"] or "(none)",
        countries=f["countries_sample"] or "(none)",
        first_seen=f["first_seen"] or "(unknown)",
        last_seen=f["last_seen"] or "(unknown)",
        evidence_refs=_render_evidence(f["evidence_refs"]),
        key_metrics=_pretty_metrics(f["key_metrics"]),
    )


def _render_evidence(j: str) -> str:
    try:
        refs = json.loads(j)
    except Exception:
        return "(none)"
    return "\n".join(f"- Section {r.get('section','?')}: {r.get('label','')}"
                     for r in refs)


def _pretty_metrics(j: str) -> str:
    try:
        obj = json.loads(j)
    except Exception:
        return j or "{}"
    return json.dumps(obj, indent=2, default=str)[:6000]


def _cache_key(provider: str, model: str, prompt: str, stem: str = "conclude") -> Path:
    sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    safe_model = model.replace("/", "_").replace(":", "_")
    return CACHE / f"{stem}_{provider}_{safe_model}_{sha}.json"


def _bullets(v) -> str:
    if isinstance(v, list):
        return "\n".join(f"- {str(x).strip()}" for x in v if str(x).strip())
    if isinstance(v, str):
        return v
    return ""


# ----------------------------------------------------------------------
# Storyline (KG-lite) synthesis — a campaign-level narrative over a GROUP of
# findings the graph stage fused by a shared entity.  This is the cross-finding
# pass: the per-finding prompt above sees one card; this one sees the whole
# operator story and explains how the pieces connect.
# ----------------------------------------------------------------------
STORYLINE_CONCLUSION_SCHEMA = pa.schema([
    ("storyline_id",      pa.string()),
    ("finding_count",     pa.uint32()),
    ("pattern_ids",       pa.string()),
    ("severity",          pa.string()),
    ("src_ip_count",      pa.uint32()),
    ("src_ips_sample",    pa.string()),
    ("asns_sample",       pa.string()),
    ("linking_entities",  pa.string()),
    ("first_seen",        pa.string()),
    ("last_seen",         pa.string()),
    ("provider",          pa.string()),
    ("model",             pa.string()),
    ("ai_title",          pa.string()),
    ("ai_campaign_summary", pa.string()),
    ("ai_why_connected",  pa.string()),
    ("ai_actor_assessment", pa.string()),
    ("ai_recommended_action", pa.string()),
    ("ai_confidence",     pa.string()),
    ("synthesized_at",    pa.timestamp("us", tz="UTC")),
])

# Human-readable meaning of the entity types the graph stage links on, so the
# prompt can tell the model WHY these findings were grouped.
_LINK_GLOSS = {
    "core_hash": "an identical compositeprint core_hash (an infrastructure-"
                 "independent behavioral fingerprint — the strongest single tell "
                 "that two findings are the same tooling/operator)",
    "chain":     "an identical packet-choreography chain (same per-connection "
                 "flag/segment sequence)",
    "ip":        "one or more shared source IP addresses",
    "asn":       "shared source ASNs (corroborated — a single shared ASN alone "
                 "was not enough to link them)",
}


STORYLINE_PROMPT_TEMPLATE = """You are a senior threat-intel analyst.  Several separately-detected findings from a long-running internet honeypot were algorithmically linked into ONE storyline because they share strong entities.  Write a single campaign-level conclusion that explains the connected story — not {n} separate ones.

# Sensor context

{sensor_context}

# Why these findings were linked

They were fused because they share: {link_reason}.

# The member findings ({n} total)

{member_block}

# Your task

Treat these as facets of (potentially) one operator/campaign.  Decide whether the linkage is convincing and tell the connected story.  Be specific and cite the shared entities + metrics above.

Reply with strict JSON (no markdown fences, no prose outside the JSON):

  ai_title              short punchy campaign title (max ~80 chars) for a report heading
  ai_campaign_summary   2-4 sentences telling the unified story across the member findings (what one operator appears to be doing)
  ai_why_connected      1-3 sentences on whether the shared entities genuinely imply ONE actor/campaign vs a coincidental overlap; state your reasoning
  ai_actor_assessment   1-2 sentences characterizing the actor (tooling maturity, infrastructure pattern, likely objective)
  ai_recommended_action 2-4 short bullets a defender can act on this week, treating the storyline as one campaign.  Each bullet a string in a JSON array.
  ai_confidence         "high" | "medium" | "low" - confidence that this is one coherent campaign vs unrelated findings that happen to share an entity

Return ONLY the JSON object."""


def _story_member_block(members: list[dict]) -> str:
    """Render the member findings compactly for the storyline prompt."""
    out = []
    for i, f in enumerate(members, 1):
        out.append(
            f"## Finding {i}: {f['pattern_title']} "
            f"(`{f['pattern_id']}`, severity {f['severity']}, "
            f"{f['src_ip_count']} source IPs)\n"
            f"metrics: {_pretty_metrics(f.get('key_metrics', '{}'))[:1500]}"
        )
    return "\n\n".join(out)


def _storyline_prompt(story: dict, members: list[dict]) -> str:
    try:
        link_counts = json.loads(story.get("linking_entities") or "{}")
    except (ValueError, TypeError):
        link_counts = {}
    reasons = [_LINK_GLOSS.get(k, k) for k in link_counts] or ["a shared entity"]
    return STORYLINE_PROMPT_TEMPLATE.format(
        n=len(members),
        sensor_context=SENSOR_CONTEXT,
        link_reason="; ".join(reasons),
        member_block=_story_member_block(members),
    )


def _load_storylines() -> list[dict]:
    path = STORY_DIR / "storylines.parquet"
    if not path.exists():
        return []
    rows = pq.read_table(path).to_pylist()
    return [r for r in rows if int(r.get("finding_count") or 0) >= 2]


def synthesize_storylines(args, provider, api_key, model,
                          findings_by_id: dict[str, dict]) -> list[dict]:
    """Campaign-level narratives for multi-finding storylines.  Returns the
    written rows (for the markdown roll-up); writes storyline_conclusions.parquet.
    Singletons are skipped — their per-finding card already covers them."""
    stories = _load_storylines()
    out_rows: list[dict] = []
    n_cached = n_called = n_failed = 0
    for s in stories:
        try:
            member_ids = json.loads(s["finding_ids"])
        except (ValueError, TypeError):
            member_ids = []
        members = [findings_by_id[m] for m in member_ids if m in findings_by_id]
        if len(members) < 2:
            continue
        prompt = _storyline_prompt(s, members)
        parsed: dict | None = None
        if provider["name"] != "none":
            cache_p = _cache_key(provider["name"], model, prompt, stem="storyline")
            if cache_p.exists() and not args.force:
                parsed = json.loads(cache_p.read_text())
                n_cached += 1
            else:
                print(f"[conclude] storyline {s['storyline_id']} "
                      f"({len(members)} findings) -> {provider['name']}/{model}...",
                      file=sys.stderr)
                try:
                    parsed = provider["call"](api_key, model, prompt)
                except Exception as e:
                    print(f"[conclude] storyline call failed: {e}", file=sys.stderr)
                if parsed is None:
                    n_failed += 1
                else:
                    cache_p.write_text(json.dumps(parsed, indent=2))
                    n_called += 1
                time.sleep(args.sleep)
        if parsed is None:
            parsed = {}
        out_rows.append({
            "storyline_id":     s["storyline_id"],
            "finding_count":    int(s["finding_count"]),
            "pattern_ids":      s["pattern_ids"],
            "severity":         s["severity"],
            "src_ip_count":     int(s["src_ip_count"]),
            "src_ips_sample":   s["src_ips_sample"],
            "asns_sample":      s["asns_sample"],
            "linking_entities": s["linking_entities"],
            "first_seen":       s["first_seen"],
            "last_seen":        s["last_seen"],
            "provider":         provider["name"],
            "model":            model,
            "ai_title":              str(parsed.get("ai_title", "")),
            "ai_campaign_summary":   str(parsed.get("ai_campaign_summary", "")),
            "ai_why_connected":      str(parsed.get("ai_why_connected", "")),
            "ai_actor_assessment":   str(parsed.get("ai_actor_assessment", "")),
            "ai_recommended_action": _bullets(parsed.get("ai_recommended_action", "")),
            "ai_confidence":         str(parsed.get("ai_confidence", "")),
            "synthesized_at":   _dt.datetime.now(_dt.timezone.utc),
        })

    STORY_DIR.mkdir(parents=True, exist_ok=True)
    pq.write_table(
        pa.Table.from_pylist(out_rows, schema=STORYLINE_CONCLUSION_SCHEMA),
        STORY_DIR / "storyline_conclusions.parquet",
        compression="zstd", compression_level=3,
    )
    if stories:
        print(f"[conclude] {len(out_rows)} storyline narratives "
              f"(cache {n_cached}, fresh {n_called}, fail {n_failed})",
              file=sys.stderr)
    return out_rows


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    findings_path = OUT_DIR / "findings.parquet"
    if not findings_path.exists():
        print(f"[conclude] no findings.parquet at {findings_path}; "
              "run correlate stage first", file=sys.stderr)
        return 0

    con = lib.duck()
    findings = [dict(zip([d[0] for d in con.execute(
        f"DESCRIBE SELECT * FROM read_parquet('{findings_path}')"
    ).fetchall()], r)) for r in con.execute(
        f"SELECT * FROM read_parquet('{findings_path}')"
    ).fetchall()]
    con.close()

    if not findings:
        print("[conclude] no findings to synthesize", file=sys.stderr)
        # still write empty parquet so downstream report stage is happy
        pq.write_table(
            pa.Table.from_pylist([], schema=CONCLUSION_SCHEMA),
            OUT_DIR / "conclusions.parquet",
            compression="zstd", compression_level=3,
        )
        (OUT_DIR / "conclusions.md").write_text(
            "# conclusions - no cross-signal findings detected this run\n"
        )
        return 0

    found = aipd.discover_provider(prefer=args.provider)
    if found is None:
        print("[conclude] no AI provider available - writing rules-only "
              "conclusions (severity + title + raw metrics only).",
              file=sys.stderr)
        provider = {"name": "none"}
        api_key = ""
        model = "n/a"
    else:
        provider, api_key = found
        model = args.model or provider["default_model"]
        print(f"[conclude] provider={provider['name']} model={model}",
              file=sys.stderr)

    out_rows: list[dict] = []
    n_cached = n_called = n_failed = 0
    for i, f in enumerate(findings):
        if args.limit and i >= args.limit:
            break
        prompt = _prompt(f)
        parsed: dict | None = None
        if provider["name"] != "none":
            cache_p = _cache_key(provider["name"], model, prompt)
            if cache_p.exists() and not args.force:
                parsed = json.loads(cache_p.read_text())
                n_cached += 1
            else:
                print(f"[conclude] {i+1}/{len(findings)} {f['pattern_id']} -> "
                      f"{provider['name']}/{model}...", file=sys.stderr)
                try:
                    parsed = provider["call"](api_key, model, prompt)
                except Exception as e:
                    print(f"[conclude] call failed: {e}", file=sys.stderr)
                if parsed is None:
                    n_failed += 1
                else:
                    cache_p.write_text(json.dumps(parsed, indent=2))
                    n_called += 1
                time.sleep(args.sleep)

        if parsed is None:
            parsed = {}

        out_rows.append({
            "finding_id":            f["finding_id"],
            "pattern_id":            f["pattern_id"],
            "pattern_title":         f["pattern_title"],
            "severity":              f["severity"],
            "category":              f["category"],
            "src_ip_count":          int(f["src_ip_count"]),
            "src_ips_sample":        f["src_ips_sample"],
            "asns_sample":           f["asns_sample"],
            "countries_sample":      f["countries_sample"],
            "key_metrics":           f["key_metrics"],
            "evidence_refs":         f["evidence_refs"],
            "report_anchor":         f["report_anchor"],
            "first_seen":            f["first_seen"],
            "last_seen":             f["last_seen"],
            "provider":              provider["name"],
            "model":                 model,
            "ai_title":              str(parsed.get("ai_title", "")),
            "ai_what":               str(parsed.get("ai_what", "")),
            "ai_why_noteworthy":     str(parsed.get("ai_why_noteworthy", "")),
            "ai_threat_model":       str(parsed.get("ai_threat_model", "")),
            "ai_risk_if_realized":   str(parsed.get("ai_risk_if_realized", "")),
            "ai_recommended_action": _bullets(parsed.get("ai_recommended_action", "")),
            "ai_confidence":         str(parsed.get("ai_confidence", "")),
            "synthesized_at":        _dt.datetime.now(_dt.timezone.utc),
        })

    pq.write_table(
        pa.Table.from_pylist(out_rows, schema=CONCLUSION_SCHEMA),
        OUT_DIR / "conclusions.parquet",
        compression="zstd", compression_level=3,
    )

    # Cross-finding pass: campaign-level narratives over the storylines the kg
    # stage fused.  Reuses the same provider/cache; writes its own parquet.
    findings_by_id = {f["finding_id"]: f for f in findings}
    story_rows = synthesize_storylines(args, provider, api_key, model, findings_by_id)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out_sorted = sorted(out_rows, key=lambda r: sev_order.get(r["severity"], 9))

    md = ["# Cross-Signal Findings & Conclusions", "",
          f"_Generated by `conclusions/synthesize.py` on "
          f"{_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}.  "
          f"AI: {provider['name']} / {model}.  "
          f"Cache hits: {n_cached}, fresh calls: {n_called}, failures: {n_failed}._",
          "",
          "Each card below is a pattern the correlator detected across two or more "
          "analyzers.  The AI-written conclusion explains *what* happened, *why* "
          "the combination of signals is anomalous, the closest real-world *threat "
          "model*, the *risk* if the same toolkit hit a production target, and "
          "*recommended actions* a defender can take now.",
          ""]

    if story_rows:
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        md += ["## Threat storylines (fused findings)", "",
               f"_{len(story_rows)} multi-finding storylines — groups of the cards "
               "below that share a strong entity (compositeprint core_hash, packet "
               "chain, or source IP) and so read as one operator/campaign._", ""]
        for sr in sorted(story_rows, key=lambda r: sev_rank.get(r["severity"], 9)):
            title = sr["ai_title"] or f"storyline {sr['storyline_id']}"
            md.append(f"### {sr['severity'].upper()} — {title}")
            md.append("")
            md.append(f"_`{sr['storyline_id']}` — {sr['finding_count']} findings — "
                      f"patterns: {sr['pattern_ids']} — confidence: "
                      f"{sr['ai_confidence'] or 'n/a'}_")
            md.append("")
            if sr["ai_campaign_summary"]:
                md.append(f"**Campaign:** {sr['ai_campaign_summary']}")
                md.append("")
            if sr["ai_why_connected"]:
                md.append(f"**Why these are one story:** {sr['ai_why_connected']}")
                md.append("")
            if sr["ai_actor_assessment"]:
                md.append(f"**Actor:** {sr['ai_actor_assessment']}")
                md.append("")
            if sr["ai_recommended_action"]:
                md.append("**Recommended action:**")
                md.append("")
                for line in sr["ai_recommended_action"].split("\n"):
                    if line.strip():
                        md.append(line if line.lstrip().startswith("-")
                                  else f"- {line.strip()}")
                md.append("")
            md.append("---")
            md.append("")

    for r in out_sorted:
        title = r["ai_title"] or r["pattern_title"]
        md.append(f"## {r['severity'].upper()} - {title}")
        md.append("")
        md.append(f"_pattern: `{r['pattern_id']}` - category: {r['category']} - "
                  f"sources: {r['src_ip_count']} - confidence: {r['ai_confidence'] or 'n/a'}_")
        md.append("")
        if r["ai_what"]:
            md.append(f"**What:** {r['ai_what']}")
            md.append("")
        if r["ai_why_noteworthy"]:
            md.append(f"**Why it's noteworthy:** {r['ai_why_noteworthy']}")
            md.append("")
        if r["ai_threat_model"]:
            md.append(f"**Threat model:** {r['ai_threat_model']}")
            md.append("")
        if r["ai_risk_if_realized"]:
            md.append(f"**Risk if realized:** {r['ai_risk_if_realized']}")
            md.append("")
        if r["ai_recommended_action"]:
            md.append("**Recommended action:**")
            md.append("")
            for line in r["ai_recommended_action"].split("\n"):
                if line.strip():
                    md.append(line if line.lstrip().startswith("-") else f"- {line.strip()}")
            md.append("")
        # Evidence + supporting numbers
        try:
            refs = json.loads(r["evidence_refs"])
        except Exception:
            refs = []
        if refs:
            md.append("**Evidence:**")
            for ref in refs:
                md.append(f"- Section {ref.get('section','?')}: {ref.get('label','')}")
            md.append("")
        if r["src_ips_sample"]:
            ips = r["src_ips_sample"].split(",")
            shown = ", ".join(f"`{ip}`" for ip in ips[:10])
            more = f" (+{len(ips)-10} more)" if len(ips) > 10 else ""
            md.append(f"**Representative source IPs:** {shown}{more}")
            md.append("")
        if r["asns_sample"]:
            md.append(f"**ASNs:** {r['asns_sample']}")
            md.append("")
        try:
            km = json.loads(r["key_metrics"])
        except Exception:
            km = {}
        if km:
            md.append("<details><summary>raw metrics</summary>")
            md.append("")
            md.append("```json")
            md.append(json.dumps(km, indent=2, default=str))
            md.append("```")
            md.append("")
            md.append("</details>")
            md.append("")
        md.append("---")
        md.append("")

    (OUT_DIR / "conclusions.md").write_text("\n".join(md) + "\n")
    print(f"[conclude] wrote {len(out_rows)} conclusions to "
          f"{OUT_DIR/'conclusions.parquet'}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", default=None)
    ap.add_argument("--model", default=None)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--sleep", type=float, default=0.3)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

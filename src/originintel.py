#!/usr/bin/env python3
"""
originintel - LLM-driven actor-group profiling.

For each top actorlink community we feed the evidence bundle
(member-IP sample, dominant ASNs/countries, shared signals, tools,
targets, timing span) to whatever AI provider auto-discovery picks
and ask it to produce a defender-facing actor profile:

  candidate_name        evocative short label (e.g. "Russian-VDS Mozi
                        cluster", "ProxyShell-mass sweep operator")
  likely_actor_class    e.g. "criminal botnet", "research scanner",
                        "state-affiliated APT", "commercial scanner"
  tooling               natural-language description of what tools they run
  ttp                   short ATT&CK-style technique list
  targets               natural-language description of who they go after
  defender_actions      concrete bullet-point recommendations
  confidence            high / medium / low

Same auto-discovery + graceful-skip behavior as aipayloaddecode:
if no provider is available, the stage logs and exits 0.

Outputs:
  output/reports/originintel/profiles.parquet + .md
  output/ai_cache/originintel_{provider}_{model}_{community_id}.json
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib

# Reuse the provider auto-discovery from aipayloaddecode
import aipayloaddecode as aid


OUT_DIR = lib.REPORTS / "originintel"
CACHE = lib.OUTPUT_DIR / "ai_cache"


PROMPT_TEMPLATE = """You are a threat-intelligence analyst.  We've clustered honeypot source IPs into a candidate "actor community" by shared behavioral signals.  Your job: produce a defender-facing actor profile.

Community evidence:
- size: {member_count} IPs
- average composite risk score (0-100): {avg_risk:.1f}
- country distribution: {countries}
- top ASNs (with member counts): {top_asns}
- shared signals connecting members (and how many edges each contributed): {shared_signals}
- dominant tool fingerprints (JA4/JA4H/JA4T + count): {dominant_tools}
- dominant targets (dst_port + hit count): {dominant_targets}
- activity window: {first_seen} -> {last_seen}
- sample IPs: {sample_ips}

IMPORTANT GUIDANCE ON CONFIDENCE AND ATTRIBUTION

You are looking at behavioral evidence from a single sensor.  This is **insufficient** for confident actor attribution in almost every case.  Do not over-claim.

- Prefer "unknown" actor class when the evidence is ambiguous.  An aggressive scan from a Chinese ASN is NOT a state actor by default - it is far more likely a commercial scanner, a misconfigured customer, or commodity malware.
- Treat "state-affiliated APT" as the highest possible bar.  You should only suggest it if the evidence shows post-exploitation activity, custom tooling, or precise targeting that cannot be explained by commodity tooling.
- Distinguish your *primary hypothesis* from *plausible alternatives*.  Real intel analysts list both.
- "high" confidence is RARE: reserve it for cases where 3+ independent strong signals converge (e.g. known C2 family + known malicious infrastructure + targeted exploitation).  Most profiles should be "low" or "medium".

Respond in strict JSON with these keys (no markdown fences, no prose outside JSON):

  candidate_name        short evocative label (max 8 words) describing this group
  likely_actor_class    one of "criminal botnet" | "research scanner" | "commercial scanner" | "state-affiliated APT" | "hacktivist" | "lone operator" | "unknown"
  alternative_classes   array of 1-3 other plausible actor_class values (in descending plausibility), or [] if the primary is overwhelming. Use this to express graded belief.
  tooling               1-2 sentence description of what tools the members appear to be running
  ttp                   3-6 short bullet points naming the ATT&CK-style techniques in play (e.g. "T1046 Network Service Discovery", "T1110 Brute Force")
  targets               1-2 sentence description of what services / vulnerabilities they go after
  defender_actions      3-5 concrete bullet points a SOC defender should take (block list, monitoring rules, etc.)
  confidence            "high" | "medium" | "low"  (default "low" unless evidence is overwhelming)
  uncertainty_notes     1-2 sentences naming what evidence is MISSING that would let you raise confidence, or what alternative interpretations are consistent with the evidence
  rationale             2-3 sentence justification of the above based on the evidence

Return ONLY the JSON object."""


PROFILE_SCHEMA = pa.schema([
    ("community_id",        pa.uint32()),
    ("provider",            pa.string()),
    ("model",               pa.string()),
    ("candidate_name",      pa.string()),
    ("likely_actor_class",  pa.string()),
    ("alternative_classes", pa.string()),
    ("tooling",             pa.string()),
    ("ttp",                 pa.string()),
    ("targets",             pa.string()),
    ("defender_actions",    pa.string()),
    ("confidence",          pa.string()),
    ("uncertainty_notes",   pa.string()),
    ("rationale",           pa.string()),
    ("profiled_at",         pa.timestamp("us", tz="UTC")),
])


def run(args: argparse.Namespace) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    found = aid.discover_provider(prefer=args.provider)
    if found is None:
        print("[origin] no AI provider available "
              "(no '*.key.txt' file paired with an installed SDK).  "
              "Skipping origin-intel stage.  This is fine - the rest of "
              "the pipeline does not depend on it.", file=sys.stderr)
        return 0
    provider, api_key = found
    model = args.model or provider["default_model"]
    print(f"[origin] provider={provider['name']} model={model}", file=sys.stderr)

    com_path = lib.REPORTS / "actorlink" / "communities.parquet"
    if not com_path.exists():
        print("[origin] no actorlink communities; run actorlink first",
              file=sys.stderr)
        return 0

    con = lib.duck()
    com_rows = con.execute(f"""
        SELECT community_id, member_count, avg_risk, countries, top_asns,
               shared_signals, dominant_tools, dominant_targets,
               first_seen, last_seen, sample_ips
        FROM read_parquet('{com_path}')
        ORDER BY member_count DESC
        LIMIT {args.limit if args.limit else 30}
    """).fetchall()
    con.close()
    print(f"[origin] {len(com_rows):,} communities to profile", file=sys.stderr)

    out_rows: list[dict] = []
    n_cached = n_called = n_failed = 0
    for r in com_rows:
        cid, mc, avg_risk, countries, top_asns, signals, tools, targets, \
            first_seen, last_seen, sample_ips = r
        # Cache key derived from full evidence bundle hash so a stable
        # community gets a stable cache slot, but evidence changes invalidate.
        bundle = json.dumps({
            "cid": int(cid), "mc": int(mc), "avg_risk": float(avg_risk or 0),
            "countries": countries, "top_asns": top_asns,
            "signals": signals, "tools": tools, "targets": targets,
            "first_seen": str(first_seen), "last_seen": str(last_seen),
            "sample_ips": sample_ips,
        }, sort_keys=True)
        bundle_sha = hashlib.sha256(bundle.encode()).hexdigest()
        cache_p = CACHE / f"originintel_{provider['name']}_{model.replace('/', '_').replace(':','_')}_{bundle_sha}.json"

        if cache_p.exists() and not args.force:
            parsed = json.loads(cache_p.read_text())
            n_cached += 1
        else:
            prompt = PROMPT_TEMPLATE.format(
                member_count=int(mc),
                avg_risk=float(avg_risk or 0),
                countries=countries or "(none)",
                top_asns=top_asns or "(none)",
                shared_signals=signals or "(none)",
                dominant_tools=tools or "(none)",
                dominant_targets=targets or "(none)",
                first_seen=first_seen,
                last_seen=last_seen,
                sample_ips=sample_ips,
            )
            print(f"[origin] profiling community {cid} ({mc} members) -> "
                  f"{provider['name']}/{model}...", file=sys.stderr)
            try:
                parsed = provider["call"](api_key, model, prompt)
            except Exception as e:
                print(f"[origin] call failed: {e}", file=sys.stderr)
                parsed = None
            if parsed is None:
                n_failed += 1
                continue
            cache_p.write_text(json.dumps(parsed, indent=2))
            n_called += 1
            time.sleep(args.sleep)

        def _bullets(x):
            if isinstance(x, list):
                return "; ".join(str(y) for y in x)
            return str(x or "")

        out_rows.append({
            "community_id":        int(cid),
            "provider":            provider["name"],
            "model":               model,
            "candidate_name":      str(parsed.get("candidate_name", "")),
            "likely_actor_class":  str(parsed.get("likely_actor_class", "")),
            "alternative_classes": _bullets(parsed.get("alternative_classes", "")),
            "tooling":             str(parsed.get("tooling", "")),
            "ttp":                 _bullets(parsed.get("ttp", "")),
            "targets":             str(parsed.get("targets", "")),
            "defender_actions":    _bullets(parsed.get("defender_actions", "")),
            "confidence":          str(parsed.get("confidence", "")),
            "uncertainty_notes":   str(parsed.get("uncertainty_notes", "")),
            "rationale":           str(parsed.get("rationale", "")),
            "profiled_at":         _dt.datetime.now(_dt.timezone.utc),
        })

    pq.write_table(pa.Table.from_pylist(out_rows, schema=PROFILE_SCHEMA),
                   OUT_DIR / "profiles.parquet",
                   compression="zstd", compression_level=3)

    md = ["# originintel - LLM-driven actor profiles", "",
          f"_Provider: `{provider['name']}` / model: `{model}`.  "
          f"Cache hits: {n_cached}, fresh calls: {n_called}, "
          f"failures: {n_failed}._", ""]
    for r in out_rows:
        md.append(f"## Community {r['community_id']} - {r['candidate_name']}")
        md.append("")
        md.append(f"- **likely actor class:** {r['likely_actor_class']}")
        if r["alternative_classes"]:
            md.append(f"- **plausible alternatives:** {r['alternative_classes']}")
        md.append(f"- **confidence:** {r['confidence']}")
        if r["uncertainty_notes"]:
            md.append(f"- **what would raise confidence:** "
                      f"{r['uncertainty_notes']}")
        md.append(f"- **tooling:** {r['tooling']}")
        md.append(f"- **targets:** {r['targets']}")
        md.append(f"- **TTPs:** {r['ttp']}")
        md.append("")
        md.append("**Defender actions:**")
        md.append("")
        for a in (r["defender_actions"] or "").split(";"):
            a = a.strip()
            if a:
                md.append(f"- {a}")
        md.append("")
        md.append(f"_rationale:_ {r['rationale']}")
        md.append("")

    (OUT_DIR / "originintel.md").write_text("\n".join(md) + "\n")
    print(f"[origin] wrote {OUT_DIR} (profiled {len(out_rows)} communities)",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", default=None)
    ap.add_argument("--model", default=None)
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--sleep", type=float, default=0.3)
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

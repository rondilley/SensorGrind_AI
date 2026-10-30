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
import re
import sys
import time
from collections import Counter
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
production estate?

BitTorrent peers that send packets to the sensor have its address in a
peer list.  The sensor data does not show where that list came from
(DHT, tracker or peer exchange), so do not name a source for it and do
not use the term "DHT"; say "peer list"."""


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
```{handshake_block}

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


def _prompt(f: dict, bt: dict | None = None) -> str:
    """``bt``: the kg handshake facts of this finding, if any."""
    block = ""
    if bt:
        block = _handshake_text(
            "the packets of a sample of this finding's sources",
            [_bt_fact_lines("This finding", bt)])
    return PROMPT_TEMPLATE.format(
        handshake_block=block,
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


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str)
                          .encode("utf-8")).hexdigest()


# Fields of a finding that its card prompt shows.  A change to any of them is a
# change to the facts; a change to the prompt text around them is not.
_CARD_FACT_FIELDS = ("pattern_id", "pattern_title", "severity", "category",
                     "src_ip_count", "src_ips_sample", "asns_sample",
                     "countries_sample", "first_seen", "last_seen",
                     "evidence_refs", "key_metrics")


def _card_facts(f: dict, bt: dict | None) -> str:
    return _sha([{k: f.get(k) for k in _CARD_FACT_FIELDS}, bt or {}])


def _story_facts(story: dict, members: list[dict]) -> str:
    return _sha([story.get("linking_entities"), story.get("handshake_facts"),
                 [{k: f.get(k) for k in ("finding_id",) + _CARD_FACT_FIELDS}
                  for f in members]])


# Provider errors after which no later call can succeed in this run.
_FATAL_ERRORS = ("credit balance", "insufficient_quota", "billing",
                 "invalid x-api-key", "authentication_error", "permission_error")


class AICache:
    """The AI outputs of the cards and storylines, and the calls that make them.

    The output file of a prompt is still keyed by sha256 of the full prompt.
    ``ai_cache/conclude_index.jsonl`` also records, for each output, the item
    id, the model, a hash of the item's facts and a hash of the shared prompt
    text (instructions).  An item whose facts did not change keeps its output
    when only the instructions change; ``--refresh-instructions`` or
    ``--redo-match`` make new outputs for it.  When a call fails or is not
    made (``--max-calls``, ``--dry-run``, a fatal provider error), the item
    keeps its newest earlier output, so a card is not left empty."""

    def __init__(self, args, provider: dict, api_key: str, model: str):
        self.INDEX = CACHE / "conclude_index.jsonl"
        self.args, self.provider, self.api_key, self.model = (
            args, provider, api_key, model)
        for k, v in (("dry_run", False), ("max_calls", 0),
                     ("refresh_instructions", False), ("redo_match", None)):
            if not hasattr(args, k):
                setattr(args, k, v)
        self.redo = re.compile(args.redo_match, re.I) if args.redo_match else None
        self.stop_reason: str | None = None
        self.calls = 0
        self.prompt_chars = 0
        self.stats: Counter = Counter()
        self.index: dict[tuple, list[dict]] = {}
        if self.INDEX.exists():
            for line in self.INDEX.read_text().splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                self.index.setdefault((e["kind"], e["id"], e["model"]), []).append(e)

    def _record(self, kind, item_id, path: Path, facts: str, instr: str) -> None:
        key = (kind, item_id, self.model)
        if any(e["file"] == path.name and e["facts"] == facts and e["instr"] == instr
               for e in self.index.get(key, [])):
            return
        e = {"kind": kind, "id": item_id, "model": self.model,
             "provider": self.provider["name"], "facts": facts, "instr": instr,
             "file": path.name,
             "at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")}
        self.index.setdefault(key, []).append(e)
        CACHE.mkdir(parents=True, exist_ok=True)
        with self.INDEX.open("a") as fh:
            fh.write(json.dumps(e) + "\n")

    def _load(self, e: dict | None) -> dict | None:
        p = CACHE / e["file"] if e else None
        return json.loads(p.read_text()) if p and p.exists() else None

    def _wanted(self, parsed: dict) -> bool:
        """True when the cached output is good enough to keep."""
        return not (self.redo and self.redo.search(json.dumps(parsed)))

    def get(self, kind: str, item_id: str, prompt: str, facts: str,
            instr: str, label: str) -> dict | None:
        if self.provider["name"] == "none":
            return None
        stem = "conclude" if kind == "card" else "storyline"
        exact = _cache_key(self.provider["name"], self.model, prompt, stem=stem)
        entries = self.index.get((kind, item_id, self.model), [])
        if exact.exists() and not self.args.force:
            parsed = json.loads(exact.read_text())
            self._record(kind, item_id, exact, facts, instr)
            if self._wanted(parsed):
                self.stats["cached"] += 1
                return parsed
        elif not (self.args.force or self.args.refresh_instructions):
            same = [e for e in entries if e["facts"] == facts]
            parsed = self._load(same[-1]) if same else None
            if parsed is not None and self._wanted(parsed):
                self.stats["reused"] += 1
                return parsed

        older = self._load(entries[-1]) if entries else None
        if self.args.dry_run:
            self.stats["would_call"] += 1
            self.prompt_chars += len(prompt)
            return older
        if self.stop_reason or (self.args.max_calls and self.calls >= self.args.max_calls):
            self.stats["not_called"] += 1
            return self._fallback(older)

        print(f"[conclude] {label} -> {self.provider['name']}/{self.model}...",
              file=sys.stderr)
        self.calls += 1
        parsed = None
        try:
            parsed = self.provider["call"](self.api_key, self.model, prompt)
        except Exception as e:
            print(f"[conclude] call failed: {e}", file=sys.stderr)
            if any(s in str(e).lower() for s in _FATAL_ERRORS):
                self.stop_reason = str(e)[:200]
                print("[conclude] fatal provider error: no more calls in this run",
                      file=sys.stderr)
        time.sleep(self.args.sleep)
        if parsed is None:
            self.stats["failed"] += 1
            return self._fallback(older)
        exact.write_text(json.dumps(parsed, indent=2))
        self._record(kind, item_id, exact, facts, instr)
        self.stats["fresh"] += 1
        return parsed

    def _fallback(self, older: dict | None) -> dict | None:
        if older is not None:
            self.stats["kept_older"] += 1
        return older

    def summary(self) -> str:
        s = self.stats
        text = (f"cached {s['cached']}, reused {s['reused']} (facts same, "
                f"instructions changed), fresh {s['fresh']}, failed {s['failed']}, "
                f"not called {s['not_called']}, kept older output {s['kept_older']}")
        if self.args.dry_run:
            text += (f"; would call {s['would_call']} "
                     f"(~{self.prompt_chars // 4:,} prompt tokens)")
        if self.stop_reason:
            text += f"; stopped: {self.stop_reason}"
        return text


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

{member_block}{handshake_block}

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


# Azureus-style peer-ID client codes (the 2 letters after the leading '-') with
# a well-known owner.  The prompt names a client only from this table; any other
# code is shown as unidentified, so the model does not invent a vendor for it.
PEER_ID_CLIENTS = {
    "AG": "Ares", "AZ": "Azureus/Vuze", "BC": "BitComet", "BI": "BiglyBT",
    "BT": "BitTorrent (mainline)", "BW": "BitTorrent Web", "DE": "Deluge",
    "FD": "Free Download Manager", "FG": "FlashGet", "KT": "KTorrent",
    "LT": "libtorrent (rakshasa)", "lt": "libtorrent (rasterbar)",
    "qB": "qBittorrent", "SD": "Thunder (Xunlei)", "TL": "Tribler",
    "TR": "Transmission", "UE": "uTorrent embedded", "UM": "uTorrent Mac",
    "UT": "uTorrent", "UW": "uTorrent Web", "XL": "Xunlei",
}


def _peer_client(prefix: str) -> str:
    code = prefix[1:3] if len(prefix) == 8 and prefix[0] == "-" else ""
    name = PEER_ID_CLIENTS.get(code)
    return f"{prefix} = {name}" if name else f"{prefix} = unidentified client"


def _handshake_block(story: dict, members: list[dict]) -> str:
    """The BitTorrent handshake facts kg read from the members' packets.  Empty
    when there are none, so the prompt (and its cache key) does not change."""
    try:
        facts = json.loads(story.get("handshake_facts") or "{}")
    except (ValueError, TypeError):
        facts = {}
    lines = [_bt_fact_lines(f"Finding {i} (`{f['pattern_id']}`)", facts[f["finding_id"]])
             for i, f in enumerate(members, 1) if facts.get(f["finding_id"])]
    return _handshake_text("the packets of a sample of each finding's sources",
                           lines)


def _load_handshake_facts() -> dict[str, dict]:
    """finding_id -> kg handshake facts, from every storyline (singletons too)."""
    path = STORY_DIR / "storylines.parquet"
    if not path.exists():
        return {}
    out: dict[str, dict] = {}
    for s in pq.read_table(path, columns=["handshake_facts"]).to_pylist():
        try:
            out.update(json.loads(s.get("handshake_facts") or "{}"))
        except (ValueError, TypeError):
            continue
    return out


def _bt_fact_lines(label: str, bt: dict) -> str:
    n, of = bt["handshake_sources"], bt["sampled_sources"]
    share = f" ({n / of:.0%})" if of else ""

    def top(key: str, name=str) -> str:
        return ", ".join(f"{name(v)} ({k:,})"
                         for v, k in bt.get(key, [])) or "(none)"
    return (
        f"- {label}: {n:,} of {of:,} sampled "
        f"sources{share} sent a BitTorrent handshake; "
        f"{bt['infohashes']:,} distinct infohashes.\n"
        f"  - protocol strings (sources): {top('protocol_strings')}\n"
        f"  - peer-ID prefixes (sources): {top('peer_id_prefixes', _peer_client)}\n"
        f"  - ports (sources): {top('ports')}")


def _handshake_text(where: str, lines: list[str]) -> str:
    if not lines:
        return ""
    return (
        "\n\n# BitTorrent handshakes in the member sources' packets\n\n"
        "These are plaintext 68-byte BitTorrent handshakes (length byte 19) "
        f"found in {where}.  A "
        "BitTorrent client sends this handshake to an address it takes to be a "
        "peer in the same torrent swarm.  It carries a 19-byte protocol string "
        "(\"BitTorrent protocol\" in the standard client; \"custom\" shows a "
        "non-text string in hex), the 20-byte infohash of the torrent, and the "
        "sender's peer ID.  The first 8 bytes of the peer ID name the client "
        "software and version (Azureus style, for example -qB4630- for "
        "qBittorrent 4.6.3).  Few infohashes and one peer-ID prefix across many "
        "sources show one client family that shares a small set of torrents.  "
        "Use these facts when you decide between a P2P swarm and an attack.  "
        "Each prefix comes with its client name from a table of well-known "
        "client codes.  Name a client only as given there.  For an "
        "\"unidentified client\", say that the client is not identified: do "
        "not guess its vendor, product or country from the prefix, the protocol "
        "string or the source networks.\n\n"
        + "\n".join(lines))


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
        handshake_block=_handshake_block(story, members),
    )


def _load_storylines() -> list[dict]:
    path = STORY_DIR / "storylines.parquet"
    if not path.exists():
        return []
    rows = pq.read_table(path).to_pylist()
    return [r for r in rows if int(r.get("finding_count") or 0) >= 2]


def _card_instr() -> str:
    """Hash of the shared card prompt text (not the facts of one finding)."""
    return _sha([SENSOR_CONTEXT, PROMPT_TEMPLATE, _handshake_text("", ["-"]),
                 PEER_ID_CLIENTS])


def _story_instr() -> str:
    return _sha([SENSOR_CONTEXT, STORYLINE_PROMPT_TEMPLATE,
                 _handshake_text("", ["-"]), PEER_ID_CLIENTS, _LINK_GLOSS])


def synthesize_storylines(args, cache: AICache,
                          findings_by_id: dict[str, dict]) -> list[dict]:
    """Campaign-level narratives for multi-finding storylines.  Returns the
    written rows (for the markdown roll-up); writes storyline_conclusions.parquet.
    Singletons are skipped — their per-finding card already covers them."""
    stories = _load_storylines()
    out_rows: list[dict] = []
    instr = _story_instr()
    for s in stories:
        try:
            member_ids = json.loads(s["finding_ids"])
        except (ValueError, TypeError):
            member_ids = []
        members = [findings_by_id[m] for m in member_ids if m in findings_by_id]
        if len(members) < 2:
            continue
        parsed = cache.get(
            "story", s["storyline_id"], _storyline_prompt(s, members),
            _story_facts(s, members), instr,
            f"storyline {s['storyline_id']} ({len(members)} findings)") or {}
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
            "provider":         cache.provider["name"],
            "model":            cache.model,
            "ai_title":              str(parsed.get("ai_title", "")),
            "ai_campaign_summary":   str(parsed.get("ai_campaign_summary", "")),
            "ai_why_connected":      str(parsed.get("ai_why_connected", "")),
            "ai_actor_assessment":   str(parsed.get("ai_actor_assessment", "")),
            "ai_recommended_action": _bullets(parsed.get("ai_recommended_action", "")),
            "ai_confidence":         str(parsed.get("ai_confidence", "")),
            "synthesized_at":   _dt.datetime.now(_dt.timezone.utc),
        })

    if args.dry_run:
        return out_rows
    STORY_DIR.mkdir(parents=True, exist_ok=True)
    pq.write_table(
        pa.Table.from_pylist(out_rows, schema=STORYLINE_CONCLUSION_SCHEMA),
        STORY_DIR / "storyline_conclusions.parquet",
        compression="zstd", compression_level=3,
    )
    if stories:
        print(f"[conclude] {len(out_rows)} storyline narratives", file=sys.stderr)
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
    cache = AICache(args, provider, api_key, model)
    instr = _card_instr()
    bt_facts = _load_handshake_facts()
    for i, f in enumerate(findings):
        if args.limit and i >= args.limit:
            break
        bt = bt_facts.get(f["finding_id"])
        parsed = cache.get(
            "card", f["finding_id"], _prompt(f, bt), _card_facts(f, bt), instr,
            f"{i+1}/{len(findings)} {f['pattern_id']}") or {}

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

    # Cross-finding pass: campaign-level narratives over the storylines the kg
    # stage fused.  Reuses the same provider/cache; writes its own parquet.
    findings_by_id = {f["finding_id"]: f for f in findings}
    story_rows = synthesize_storylines(args, cache, findings_by_id)
    print(f"[conclude] AI outputs: {cache.summary()}", file=sys.stderr)
    if args.dry_run:
        print("[conclude] dry run: no calls made, no files written", file=sys.stderr)
        return 0

    pq.write_table(
        pa.Table.from_pylist(out_rows, schema=CONCLUSION_SCHEMA),
        OUT_DIR / "conclusions.parquet",
        compression="zstd", compression_level=3,
    )

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out_sorted = sorted(out_rows, key=lambda r: sev_order.get(r["severity"], 9))

    md = ["# Cross-Signal Findings & Conclusions", "",
          f"_Generated by `conclusions/synthesize.py` on "
          f"{_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}.  "
          f"AI: {provider['name']} / {model}.  "
          f"AI outputs: {cache.summary()}._",
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
    ap.add_argument("--dry-run", action="store_true",
                    help="count the calls a run would make; make no calls, write no files")
    ap.add_argument("--max-calls", type=int, default=0,
                    help="stop calling the provider after N calls (0 = no limit)")
    ap.add_argument("--refresh-instructions", action="store_true",
                    help="make new outputs when only the shared prompt text changed")
    ap.add_argument("--redo-match", default=None, metavar="REGEX",
                    help="make new outputs only for items whose cached output matches")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

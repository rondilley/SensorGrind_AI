"""Storyline (cross-finding) synthesis contracts for conclusions/synthesize.

Exercises the campaign-narrative pass WITHOUT any LLM call by using the
"none" provider (the no-API-key path), so it runs offline and never spends
tokens.  Pins prompt construction and the parquet contract.
"""
from __future__ import annotations

import argparse
import json

import pyarrow as pa
import pyarrow.parquet as pq

from conclusions import synthesize


def _finding(fid, pattern, sev="high", ips=("1.1.1.1",), km=None):
    return {
        "finding_id": fid, "pattern_id": pattern, "pattern_title": pattern,
        "severity": sev, "category": "c", "src_ip_count": len(ips),
        "src_ips_sample": ",".join(ips), "asns_sample": "AS1",
        "countries_sample": "US", "key_metrics": json.dumps(km or {}),
        "evidence_refs": "[]", "report_anchor": "", "first_seen": "", "last_seen": "",
    }


def _story(sid, finding_ids, link, sev="high"):
    return {
        "storyline_id": sid, "finding_count": len(finding_ids),
        "finding_ids": json.dumps(finding_ids), "pattern_ids": "a,b",
        "severity": sev, "categories": "c", "src_ip_count": 3,
        "src_ips_sample": "1.1.1.1", "asns_sample": "AS1", "countries_sample": "US",
        "linking_entities": json.dumps(link), "link_weight_total": 5.0,
        "first_seen": "", "last_seen": "",
    }


def test_storyline_prompt_names_members_and_link_reason():
    members = [_finding("f1", "fp_rotation"), _finding("f2", "anom_chain")]
    story = _story("story_abc", ["f1", "f2"], {"core_hash": 1})
    p = synthesize._storyline_prompt(story, members)
    assert "fp_rotation" in p and "anom_chain" in p
    # the human gloss for core_hash must reach the prompt so the model knows WHY
    assert "compositeprint core_hash" in p
    assert "2 total" in p  # member count rendered


def test_synthesize_storylines_writes_parquet_without_llm(tmp_path, monkeypatch):
    story_dir = tmp_path / "storylines"
    story_dir.mkdir()
    monkeypatch.setattr(synthesize, "STORY_DIR", story_dir)
    monkeypatch.setattr(synthesize, "CACHE", tmp_path / "cache")

    # a multi-finding storyline + a singleton (singleton must be ignored)
    rows = [
        _story("story_multi", ["f1", "f2"], {"ip": 1}),
        {**_story("story_solo", ["f3"], {}), "finding_count": 1,
         "finding_ids": json.dumps(["f3"])},
    ]
    # storylines.parquet only carries multi-finding rows in practice, but assert
    # the >=2 guard regardless by including a degenerate one.
    pq.write_table(pa.Table.from_pylist(
        [r for r in rows if r["finding_count"] >= 2]), story_dir / "storylines.parquet")

    findings_by_id = {
        "f1": _finding("f1", "fp_rotation"),
        "f2": _finding("f2", "anom_chain"),
    }
    args = argparse.Namespace(force=False, sleep=0.0)
    cache = synthesize.AICache(args, {"name": "none"}, "", "n/a")
    out = synthesize.synthesize_storylines(args, cache, findings_by_id)

    assert len(out) == 1 and out[0]["storyline_id"] == "story_multi"
    # no-LLM path => empty ai fields, but row is well-formed under the schema
    assert out[0]["ai_campaign_summary"] == ""
    t = pq.read_table(story_dir / "storyline_conclusions.parquet")
    assert t.num_rows == 1
    assert t.schema.equals(synthesize.STORYLINE_CONCLUSION_SCHEMA)


def test_no_storylines_file_yields_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(synthesize, "STORY_DIR", tmp_path / "nope")
    monkeypatch.setattr(synthesize, "CACHE", tmp_path / "cache")
    args = argparse.Namespace(force=False, sleep=0.0)
    cache = synthesize.AICache(args, {"name": "none"}, "", "n/a")
    out = synthesize.synthesize_storylines(args, cache, {})
    assert out == []
    # still writes a valid empty parquet for downstream report
    t = pq.read_table(tmp_path / "nope" / "storyline_conclusions.parquet")
    assert t.num_rows == 0


def test_storyline_prompt_without_handshake_facts_has_no_section():
    members = [_finding("f1", "fp_rotation"), _finding("f2", "anom_chain")]
    p = synthesize._storyline_prompt(_story("s1", ["f1", "f2"], {"ip": 1}), members)
    assert "BitTorrent handshakes" not in p


def test_storyline_prompt_gives_the_handshake_facts():
    members = [_finding("f1", "burst_chain_23142"), _finding("f2", "anom_chain")]
    story = _story("s1", ["f1", "f2"], {"chain": 1})
    story["handshake_facts"] = json.dumps({"f1": {
        "handshake_sources": 1999, "sampled_sources": 2000, "infohashes": 1,
        "protocol_strings": [["custom 49020f57", 1999]],
        "peer_id_prefixes": [["-DL3790-", 1999]],
        "ports": [["tcp/23142", 1999]]}})
    p = synthesize._storyline_prompt(story, members)
    assert "# BitTorrent handshakes" in p
    assert "Finding 1 (`burst_chain_23142`): 1,999 of 2,000 sampled sources (100%)" in p
    assert "-DL3790- = unidentified client (1,999)" in p
    assert "custom 49020f57 (1,999)" in p
    assert "Finding 2" not in p.split("# BitTorrent handshakes")[1]


def test_peer_client_names_only_known_codes():
    assert synthesize._peer_client("-qB5120-") == "-qB5120- = qBittorrent"
    assert synthesize._peer_client("-DL3790-") == "-DL3790- = unidentified client"
    assert synthesize._peer_client("hex 0000005e") == "hex 0000005e = unidentified client"


_BT = {"handshake_sources": 55, "sampled_sources": 55, "infohashes": 1,
       "protocol_strings": [["BitTorrent protocol", 54]],
       "peer_id_prefixes": [["-qB5120-", 26]], "ports": [["tcp/20211", 54]]}


def test_finding_prompt_without_handshake_facts_is_unchanged():
    f = _finding("f1", "neuro_hdc_group")
    p = synthesize._prompt(f)
    assert "BitTorrent handshakes" not in p
    assert synthesize._prompt(f, None) == p == synthesize._prompt(f, {})
    assert "```\n\n# Your task" in p   # the old layout, so old cache keys hold


def test_finding_prompt_gives_the_handshake_facts():
    p = synthesize._prompt(_finding("f1", "neuro_hdc_group"), _BT)
    block = p.split("# BitTorrent handshakes")[1].split("# Your task")[0]
    assert "this finding's sources" in block
    assert "This finding: 55 of 55 sampled sources (100%)" in block
    assert "-qB5120- = qBittorrent (26)" in block


def test_load_handshake_facts_reads_singletons_too(tmp_path, monkeypatch):
    monkeypatch.setattr(synthesize, "STORY_DIR", tmp_path)
    pq.write_table(pa.Table.from_pylist([
        {"finding_count": 1, "handshake_facts": json.dumps({"f1": _BT})},
        {"finding_count": 2, "handshake_facts": json.dumps({"f2": _BT})},
        {"finding_count": 1, "handshake_facts": None},
    ]), tmp_path / "storylines.parquet")
    assert set(synthesize._load_handshake_facts()) == {"f1", "f2"}


# --- AICache: reuse across instruction changes, budget, fatal errors ----------

def _cache_args(**kw):
    base = dict(force=False, sleep=0.0, dry_run=False, max_calls=0,
                refresh_instructions=False, redo_match=None)
    return argparse.Namespace(**{**base, **kw})


def _provider(replies: list):
    """A provider whose call returns (or raises) the next item of ``replies``
    and records each prompt it was given."""
    seen: list[str] = []

    def call(api_key, model, prompt):
        seen.append(prompt)
        r = replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r
    return {"name": "test", "call": call}, seen


def _get(cache, prompt, facts="F1", instr="I1", item="f1"):
    return cache.get("card", item, prompt, facts, instr, item)


def test_cache_reuses_output_when_only_instructions_change(tmp_path, monkeypatch):
    monkeypatch.setattr(synthesize, "CACHE", tmp_path)
    prov, seen = _provider([{"ai_title": "first"}])
    assert _get(synthesize.AICache(_cache_args(), prov, "", "m"),
                "prompt v1")["ai_title"] == "first"
    c = synthesize.AICache(_cache_args(), prov, "", "m")
    assert _get(c, "prompt v2", instr="I2")["ai_title"] == "first"
    assert len(seen) == 1 and c.stats["reused"] == 1


def test_cache_calls_again_when_facts_change(tmp_path, monkeypatch):
    monkeypatch.setattr(synthesize, "CACHE", tmp_path)
    prov, seen = _provider([{"ai_title": "first"}, {"ai_title": "second"}])
    _get(synthesize.AICache(_cache_args(), prov, "", "m"), "prompt v1")
    c = synthesize.AICache(_cache_args(), prov, "", "m")
    assert _get(c, "prompt v2", facts="F2")["ai_title"] == "second"
    assert len(seen) == 2


def test_cache_redo_match_selects_only_matching_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(synthesize, "CACHE", tmp_path)
    prov, seen = _provider([{"ai_what": "a DHT node"}, {"ai_what": "a peer list"},
                            {"ai_what": "peer list now"}])
    c = synthesize.AICache(_cache_args(), prov, "", "m")
    _get(c, "p1", item="f1")
    _get(c, "p2", item="f2")
    c = synthesize.AICache(_cache_args(redo_match="dht"), prov, "", "m")
    assert _get(c, "p1b", instr="I2", item="f1")["ai_what"] == "peer list now"
    assert _get(c, "p2b", instr="I2", item="f2")["ai_what"] == "a peer list"
    assert seen == ["p1", "p2", "p1b"]


def test_cache_stops_after_fatal_error_and_keeps_older_output(tmp_path, monkeypatch):
    monkeypatch.setattr(synthesize, "CACHE", tmp_path)
    prov, seen = _provider([{"ai_title": "old"},
                            RuntimeError("Your credit balance is too low")])
    _get(synthesize.AICache(_cache_args(), prov, "", "m"), "p1")
    c = synthesize.AICache(_cache_args(), prov, "", "m")
    assert _get(c, "p2", facts="F2")["ai_title"] == "old"
    assert _get(c, "p3", facts="F3") == {"ai_title": "old"}
    assert len(seen) == 2 and c.stop_reason and c.stats["not_called"] == 1


def test_cache_dry_run_and_max_calls_make_no_extra_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(synthesize, "CACHE", tmp_path)
    prov, seen = _provider([{"ai_title": "x"}])
    c = synthesize.AICache(_cache_args(dry_run=True), prov, "", "m")
    assert _get(c, "p1") is None and c.stats["would_call"] == 1 and not seen
    c = synthesize.AICache(_cache_args(max_calls=1), prov, "", "m")
    _get(c, "p1", item="f1")
    assert _get(c, "p2", item="f2") is None and len(seen) == 1

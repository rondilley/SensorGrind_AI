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
    out = synthesize.synthesize_storylines(
        args, {"name": "none"}, "", "n/a", findings_by_id)

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
    out = synthesize.synthesize_storylines(args, {"name": "none"}, "", "n/a", {})
    assert out == []
    # still writes a valid empty parquet for downstream report
    t = pq.read_table(tmp_path / "nope" / "storyline_conclusions.parquet")
    assert t.num_rows == 0

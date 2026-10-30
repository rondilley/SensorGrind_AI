"""conclusions/verdict contracts.

Wiring tests run anywhere.  The rest run on the real verdict snapshot
(output/conclusions/verdicts.parquet, written by the verdict stage from the
real corpus) and skip when it is absent; no input is fabricated.
"""
from __future__ import annotations

import json

import pyarrow.parquet as pq
import pytest

import evolve
from bench import verdict_eval
from conclusions import verdict

VERDICTS = verdict.OUT_DIR / "verdicts.parquet"


def _rows() -> list[dict]:
    if not VERDICTS.exists():
        pytest.skip("no verdicts.parquet; run the verdict stage")
    return pq.read_table(VERDICTS).to_pylist()


def test_rule_ids_unique_and_verdicts_known():
    ids = [r.rule_id for r in verdict.RULES]
    assert len(ids) == len(set(ids))
    assert {r.verdict for r in verdict.RULES} <= set(verdict.ACTIONS)
    assert set(verdict.VERDICT_ORDER) == set(verdict.ACTIONS)


def test_conclude_is_opt_in_and_verdict_is_default():
    assert "conclude" in evolve.OPT_IN
    assert "verdict" in evolve.STAGES and "verdict" not in evolve.OPT_IN
    assert "correlate" in evolve.EXPLICIT_DEPS["verdict"]


@pytest.mark.corpus
def test_stored_facts_reproduce_stored_verdict():
    # decide() is pure: the facts saved with each row give the same verdict,
    # rule, reason and note.  Fails if the rule table changed without a rerun.
    for r in _rows():
        d = verdict.decide(json.loads(r["facts"]))
        assert (d["verdict"], d["rule_id"], d["why"], d["note"]) == (
            r["verdict"], r["rule_id"], r["why"], r["note"]), r["finding_id"]


@pytest.mark.corpus
def test_no_credential_verdict_on_server_first_service():
    # The sensor never answers a server-first protocol, so a login there
    # cannot be seen; a credential verdict on one would have no evidence.
    for r in _rows():
        if r["verdict"] == "credential_attack" and r["rule_id"] != "http_credentials":
            assert r["service"] not in verdict.SERVER_FIRST, r["finding_id"]


@pytest.mark.corpus
def test_bittorrent_majority_is_benign_p2p():
    for r in _rows():
        f = json.loads(r["facts"])
        if verdict._is_p2p_by_members(f):
            assert r["verdict"] == "benign_p2p", r["finding_id"]
        if f["scanner_share"] >= verdict.SCANNER_SHARE:
            assert r["verdict"] != "benign_p2p", r["finding_id"]


@pytest.mark.corpus
def test_every_verdict_names_its_rule_and_action():
    for r in _rows():
        assert r["action"] == verdict.ACTIONS[r["verdict"]]
        assert bool(r["rule_id"]) == (r["verdict"] != "unclassified")


@pytest.mark.corpus
def test_llm_class_is_the_headline_claim():
    # On the cached LLM cards, a "recon ... feeding credential spray" text is
    # the recon class; benign BitTorrent text is benign_p2p.
    path = verdict_eval.CONCL
    if not path.exists():
        pytest.skip("no cached conclusions.parquet")
    texts = [r["ai_threat_model"] or "" for r in
             pq.read_table(path, columns=["ai_threat_model"]).to_pylist()]
    for t in texts:
        c = verdict_eval.opus_class(t)
        if t.lower().startswith("not an attack") and "bittorrent" in t.lower():
            assert c == "benign_p2p", t[:80]
        if t.lower().startswith("internet-wide service enumeration"):
            assert c == "service_recon", t[:80]


@pytest.mark.corpus
def test_each_finding_is_in_exactly_one_problem():
    rows = _rows()
    path = verdict.OUT_DIR / "problems.parquet"
    if not path.exists():
        pytest.skip("no problems.parquet; run the verdict stage")
    probs = pq.read_table(path).to_pylist()
    ids = [f for p in probs for f in json.loads(p["finding_ids"])]
    assert sorted(ids) == sorted(r["finding_id"] for r in rows)
    by_id = {r["finding_id"]: r for r in rows}
    for p in probs:
        members = [by_id[f] for f in json.loads(p["finding_ids"])]
        assert {(m["verdict"], m["target"]) for m in members} == {(p["verdict"], p["target"])}
        assert p["sources"] <= sum(m["n_members"] for m in members)


@pytest.mark.corpus
def test_context_only_when_most_asns_are_not_bulletproof():
    for r in _rows():
        f = json.loads(r["facts"])
        if r["verdict"] == "context":
            assert f["asn_known"] and f["asn_bulletproof_share"] < verdict.BULLETPROOF_SHARE
        if r["rule_id"] == "hostile_infra" and f["n_members"] == 0:
            assert f["asn_bulletproof_share"] >= verdict.BULLETPROOF_SHARE


@pytest.mark.corpus
def test_p2p_port_needs_other_p2p_findings_on_the_port():
    for r in _rows():
        if r["rule_id"] == "p2p_port":
            f = json.loads(r["facts"])
            assert f["port_p2p_findings"] >= 1
            assert not verdict._is_p2p_by_members(f)


@pytest.mark.corpus
def test_service_probe_means_service_l7_is_a_minority():
    for r in _rows():
        if r["rule_id"] == "service_probe":
            f = json.loads(r["facts"])
            assert f["l7_share"].get(f["service"], 0.0) < verdict.L7_SHARE

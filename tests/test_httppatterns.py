"""Unit tests for httppatterns (Track B) pure helpers + DAG registration.

String-algorithm tests (template generalization, request-line parsing) on
tiny constructed inputs — not honeypot data, so valid under no-synthetic-data.
The clustering pipeline itself is exercised via the `corpus` marker.
"""
from __future__ import annotations

import pytest

import httppatterns as hp


def test_httppatterns_wired_into_dag():
    import evolve
    assert "httppatterns" in evolve.STAGES
    deps = evolve.build_dependency_graph()
    assert "httppatterns" in deps["report"], "report must consume httppatterns"
    assert "httppatterns" in deps["metrics"], "metrics must consume httppatterns"
    evolve.topological_order(deps, list(evolve.STAGES))  # acyclic w/ new stage


def test_first_line_strips_headers_and_crlf():
    raw = "GET /a HTTP/1.1\r\nHost: x\r\n\r\nbody"
    assert hp.first_line(raw) == "GET /a HTTP/1.1"


def test_generalize_collapses_variable_segment():
    lines = ["GET /shop/1 HTTP/1.1", "GET /shop/2 HTTP/1.1", "GET /shop/3 HTTP/1.1"]
    assert hp.generalize_requests(lines) == "GET /shop/*"


def test_generalize_keeps_constant_path():
    lines = ["POST /boaform/admin/formLogin HTTP/1.1"] * 5
    assert hp.generalize_requests(lines) == "POST /boaform/admin/formLogin"


def test_generalize_marks_query_present():
    lines = ["GET /index.php?id=1 HTTP/1.1", "GET /index.php?id=2 HTTP/1.1"]
    out = hp.generalize_requests(lines)
    assert out.startswith("GET /index.php") and out.endswith("?*")


def test_generalize_picks_majority_method():
    lines = ["GET /a HTTP/1.1", "GET /a HTTP/1.1", "POST /a HTTP/1.1"]
    assert hp.generalize_requests(lines).startswith("GET ")


def test_generalize_non_http_falls_back_to_prefix():
    lines = ["\x16\x03\x01 garbage one", "\x16\x03\x01 garbage two"]
    out = hp.generalize_requests(lines)
    assert out != "" and "garbage" in out or out == "(non-standard)"


def test_template_path_strips_annotation():
    assert hp.template_path("GET /boaform/admin  [UA: x]") == "/boaform/admin"
    assert hp.template_path("OPTIONS /rtsp://h:554/*") == "/rtsp://h:554/*"


def test_is_novel_against_probesigs():
    known = {"/.env", "/manager/html"}
    assert hp.is_novel("GET /boaform/admin/formLogin", known) is True
    assert hp.is_novel("GET /.env  [UA: x]", known) is False  # matches a signature
    assert hp.is_novel("GET /anything", set()) is True        # no sigs -> all novel


@pytest.mark.corpus
def test_run_clusters_real_http_and_emits_membership(tmp_path, monkeypatch):
    import argparse
    args = argparse.Namespace(cluster_sample=4000, min_cluster_size=8,
                              min_samples=4, svd_dims=20, assign_min_cos=0.5,
                              limit_templates=10)
    rep = hp.run(args)
    assert rep.name == "http_patterns"
    assert isinstance(rep.rows, list)
    # membership stashed on the report (written by main(), not run())
    assert hasattr(rep, "membership") and isinstance(rep.membership, list)
    if rep.membership:
        sha, cid = rep.membership[0]
        assert isinstance(sha, (bytes, bytearray)) and len(sha) == 32
        assert isinstance(cid, int)

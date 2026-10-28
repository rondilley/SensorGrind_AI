"""Regression tests for the mermaid generators in report/render.py.

Every assertion here corresponds to a bug that actually shipped and broke
PDF / VS Code / GitHub rendering (2026-06-04): unescaped '&', comma-shifted
sankey CSV, directed cycles in sankey, and mid-token label truncation.
See memory: mermaid-render-gotchas.
"""
from __future__ import annotations

from report import render as r


# ---- mm_text: cross-renderer label sanitization -------------------------

def test_mm_text_neutralizes_ampersand_quote_pipe_comma():
    out = r.mm_text('AT&T "Big" | Co, Inc.')
    assert "&" not in out
    assert '"' not in out
    assert "|" not in out
    assert "," not in out


def test_mm_text_strips_trailing_punctuation_from_truncation():
    # "AT&T Enterprises, LLC"[:18] -> "AT&T Enterprises, " was the real input
    assert r.mm_text("AT&T Enterprises, ").rstrip() == r.mm_text("AT&T Enterprises, ")
    assert not r.mm_text("AT&T Enterprises, ").endswith((",", " "))


def test_mm_id_is_identifier_safe():
    assert r.mm_id("AS7018 AT&T, Inc.") .replace("_", "").isalnum()
    assert r.mm_id("") == "n"


# ---- flowchart ----------------------------------------------------------

def test_flowchart_labels_have_no_raw_special_chars():
    block = r.mermaid_flowchart(
        "LR",
        [("AS7018", "AS7018 AT&T Enterprises, LLC")],
        [("AS7018", "AS7018", "5")],  # self-loop edge is fine in flowchart
    )
    body = "\n".join(l for l in block.splitlines() if l.strip().startswith("AS"))
    assert "&" not in body and '"AS7018 AT and T' in block


# ---- sankey: CSV quoting + acyclic --------------------------------------

def test_sankey_quotes_fields_so_commas_dont_shift_columns():
    block = r.mermaid_sankey([("A, Inc", "B Corp", 10)])
    data = [l for l in block.splitlines() if l and "," in l and "sankey" not in l]
    # each data row must parse to exactly 3 fields once quoted fields are honored
    for line in data:
        assert line.startswith('"'), f"sankey field not quoted: {line}"


def test_sankey_drops_directed_cycles_and_self_loops():
    rows = [("A", "B", 100), ("B", "A", 90), ("C", "C", 50)]
    kept = r._sankey_acyclic(rows)
    pairs = {(s, t) for s, t, _ in kept}
    assert ("A", "B") in pairs           # heavier direction survives
    assert ("B", "A") not in pairs       # back-edge dropped (would be a cycle)
    assert ("C", "C") not in pairs       # self-loop dropped


def test_sankey_acyclic_keeps_heaviest_direction():
    kept = r._sankey_acyclic([("A", "B", 5), ("B", "A", 99)])
    assert kept == [("B", "A", 99)]


# ---- gantt --------------------------------------------------------------

def test_gantt_task_names_have_no_colon_or_comma():
    block = r.mermaid_gantt("camp", [("AS1 AT&T, Inc.", "5ip",
                                      "2026-05-01", "2026-05-02")])
    task_lines = [l for l in block.splitlines()
                  if l.strip() and ":" in l and "section" not in l
                  and not l.strip().startswith(("gantt", "dateFormat",
                  "title", "axisFormat", "tickInterval", "weekday"))]
    for l in task_lines:
        name = l.split(":")[0]
        assert "," not in name, f"comma in gantt task name: {l}"


# ---- mm_trunc: word-boundary truncation ---------------------------------

def test_mm_trunc_does_not_cut_mid_word():
    assert r.mm_trunc("Charter Communications", 18) == "Charter"
    assert r.mm_trunc("Comcast", 18) == "Comcast"  # short -> unchanged


def test_mm_trunc_hard_cut_when_first_word_too_long():
    assert r.mm_trunc("Supercalifragilistic", 8) == "Supercal"

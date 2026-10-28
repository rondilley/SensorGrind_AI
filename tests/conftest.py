"""Shared test fixtures and path setup.

Puts ``src/`` on sys.path so analyzer modules import the same way they do
under evolve.py (which runs them as scripts with that insert). Also gives
tests an isolated output dir so nothing touches the real corpus outputs.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _corpus_present() -> bool:
    """True if the real parsed corpus exists (packets parquet partitions)."""
    pkts = REPO_ROOT / "output" / "parquet" / "packets"
    return pkts.is_dir() and any(pkts.rglob("*.parquet"))


def pytest_collection_modifyitems(config, items):
    """Skip @pytest.mark.corpus tests when the real dataset isn't present —
    we never fabricate honeypot input, so these only run on a populated box."""
    if _corpus_present():
        return
    skip = pytest.mark.skip(reason="real corpus not present (output/parquet/packets)")
    for item in items:
        if "corpus" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def tmp_output(tmp_path, monkeypatch):
    """Redirect sg.lib output dirs into a tmp dir for write-contract tests."""
    import importlib
    monkeypatch.setenv("SG_OUTPUT", str(tmp_path / "output"))
    monkeypatch.setenv("SG_REPORTS", str(tmp_path / "output" / "reports"))
    monkeypatch.setenv("SG_PARQUET", str(tmp_path / "output" / "parquet"))
    import sg.lib as lib
    importlib.reload(lib)
    yield lib
    importlib.reload(lib)  # restore module-level paths for later tests

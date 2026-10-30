"""evolve STAGE_IO contracts for the analyzers and chainfp stages."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import evolve
import sgquery


def test_analyzer_list_matches_sgquery():
    assert list(evolve._ANALYZERS) == sgquery.ANALYZER_ORDER


def test_analyzer_contract_covers_every_module():
    io = evolve.STAGE_IO["analyzers"]
    for m in sgquery.ANALYZER_ORDER:
        assert f"src/{m}.py" in io["inputs"]
        assert f"output/reports/{m}/{m}.parquet" in io["outputs"]


def test_chainfp_contract_sources():
    io = evolve.STAGE_IO["chainfp"]
    assert "src/chainfp.py" in io["inputs"]
    assert "output/reports/chainfp/chainfp.parquet" in io["outputs"]

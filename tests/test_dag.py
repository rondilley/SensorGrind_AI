"""DAG integrity contracts for evolve.py.

These are pure-structure checks (no data, no subprocess) that catch the
class of bug that silently breaks a full run: a dep edge pointing at a
stage that was renamed/removed, a cycle, a stage whose entrypoint script
doesn't exist, or `report` not depending on a producer it reads.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import evolve

REPO_ROOT = Path(evolve.__file__).resolve().parents[1]


def test_every_stage_entrypoint_exists():
    """Each stage's first argv token is a real .py file on disk."""
    missing = []
    for stage, argv in evolve.STAGES.items():
        script = Path(argv[0])
        if not script.exists():
            missing.append((stage, str(script)))
    assert not missing, f"stages with missing entrypoints: {missing}"


def test_explicit_deps_reference_real_stages():
    unknown = {
        s: [p for p in parents if p not in evolve.STAGES]
        for s, parents in evolve.EXPLICIT_DEPS.items()
        if any(p not in evolve.STAGES for p in parents)
    }
    assert not unknown, f"EXPLICIT_DEPS referencing unknown stages: {unknown}"
    bad_keys = [s for s in evolve.EXPLICIT_DEPS if s not in evolve.STAGES]
    assert not bad_keys, f"EXPLICIT_DEPS keys that aren't stages: {bad_keys}"


def test_stage_io_keys_and_globs_well_formed():
    for s, io in evolve.STAGE_IO.items():
        assert s in evolve.STAGES, f"STAGE_IO entry for unknown stage {s}"
        assert set(io).issubset({"inputs", "outputs"}), f"{s}: stray IO keys"
        assert io.get("outputs"), f"{s}: STAGE_IO entry must declare outputs"


def test_dependency_graph_is_acyclic_over_all_stages():
    deps = evolve.build_dependency_graph()
    # topological_order raises RuntimeError on a cycle.
    order = evolve.topological_order(deps, list(evolve.STAGES.keys()))
    assert set(order) == set(evolve.STAGES), "topo order dropped/added stages"


def test_topological_order_respects_dependencies():
    deps = evolve.build_dependency_graph()
    order = evolve.topological_order(deps, list(evolve.STAGES.keys()))
    pos = {s: i for i, s in enumerate(order)}
    for s, parents in deps.items():
        for p in parents:
            assert pos[p] < pos[s], f"{p} must run before {s}"


def test_report_depends_on_its_producers():
    """report reads per-analyzer parquet; a producer missing from its deps
    means a fresh run could render a stale/absent section. Spot-check the
    analyzers report is known to consume."""
    deps = evolve.build_dependency_graph()
    report_parents = deps["report"]
    for producer in ("correlate", "conclude", "risk", "campaignmigration",
                     "compositeprint", "chainfp", "originintel"):
        assert producer in report_parents, f"report missing dep on {producer}"

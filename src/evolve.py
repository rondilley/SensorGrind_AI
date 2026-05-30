#!/usr/bin/env python3
"""
evolve — orchestrator for the SensorGrind_AI v2 learn-and-evolve loop.

Sequence of stages (each runnable independently):

  1. analyzers     — run the 19 base analyzers (sgquery.py)
  2. features      — build the per-IP feature snapshot (build_ip_features)
  3. model         — train the threat classifier on bootstrap labels
  4. score         — score every IP with the current threat classifier
  5. risk          — composite risk score + tier assignment
  6. dossiers      — markdown dossiers for high-risk IPs
  7. mining        — FP-Growth itemset mining
  8. promote       — auto-promote behavioral, queue content
  9. longitudinal  — change-point detection on top IPs

Usage:
  python evolve.py                  # full pipeline (skips fresh stages)
  python evolve.py model score risk # subset of stages
  python evolve.py --skip analyzers # everything except analyzers
  python evolve.py --force          # ignore freshness cache, rerun all
  python evolve.py --no-cache       # don't read OR write freshness cache
  python evolve.py --parallel 4     # run independent stages on 4 workers
                                    # (DAG mode, respects all the flags above)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import hashlib
import json
import subprocess
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor, Future, wait, FIRST_COMPLETED
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
PY = REPO_ROOT / "venv" / "bin" / "python"

STAGES: dict[str, list[str]] = {
    "analyzers":    [str(SRC / "sgquery.py")],
    "features":     [str(SRC / "features" / "build_ip_features.py")],
    "model":        [str(SRC / "models" / "train_threat_classifier.py")],
    "score":        [str(SRC / "models" / "score_threats.py")],
    "risk":         [str(SRC / "risk" / "compute_risk_score.py")],
    "dossiers":     [str(SRC / "risk" / "risk_dossier.py"), "--min-tier", "high", "--limit", "100"],
    "mining":       [str(SRC / "mining" / "mine_itemsets.py")],
    "promote":      [str(SRC / "mining" / "promote_patterns.py")],
    "longitudinal": [str(SRC / "longitudinal" / "detect_changepoints.py")],
    "chains":       [str(SRC / "longitudinal" / "attack_chains.py")],
    "sequences":    [str(SRC / "mining" / "mine_sequences.py")],
    "coordination": [str(SRC / "longitudinal" / "detect_coordination.py")],
    "actors":       [str(SRC / "models" / "train_actor_clusterer.py")],
    "drift":        [str(SRC / "models" / "detect_drift.py")],
    "rotation":     [str(SRC / "longitudinal" / "infra_rotation.py")],
    "cross_modal":  [str(SRC / "longitudinal" / "cross_modal_lag.py")],
    "survival":     [str(SRC / "longitudinal" / "survival_analysis.py")],
    # --- v2.2 deep-analysis additions ---
    "pktanalysis":     [str(SRC / "pktanalysis.py")],
    "payloadanalysis": [str(SRC / "payloadanalysis.py")],
    "pacing":          [str(SRC / "pacing.py")],
    "landscape":       [str(SRC / "landscape.py")],
    "protocolanomaly": [str(SRC / "protocolanomaly.py")],
    "isc_compare":     [str(SRC / "isc_compare.py")],
    "nonipproto":      [str(SRC / "nonipproto.py")],
    "aipayloaddecode": [str(SRC / "aipayloaddecode.py")],
    # --- v2.3 origin & actor-attribution ---
    "asnintel":        [str(SRC / "asnintel.py")],
    "cidrintel":       [str(SRC / "cidrintel.py")],
    "tooling":         [str(SRC / "tooling.py")],
    "actorlink":       [str(SRC / "actorlink.py")],
    "originintel":     [str(SRC / "originintel.py")],
    # --- v2.5 blind-spot analyzers added per multi-AI methodology review ---
    "slowlow":       [str(SRC / "slowlow.py")],
    "dnstlsintel":   [str(SRC / "dnstlsintel.py")],
    "selfmimic":     [str(SRC / "selfmimic.py")],
    "adversarysim":  [str(SRC / "adversarysim.py")],
    # --- v2.6 cross-analyzer correlator + AI-written conclusions ---
    "correlate":    [str(SRC / "conclusions" / "correlate.py")],
    "conclude":     [str(SRC / "conclusions" / "synthesize.py")],
    "report":       [str(SRC / "report" / "comprehensive_report.py")],
    # --- v2.4 cross-AI review of the tool itself ---
    "aireview":     [str(SRC / "aireview.py")],
}
ORDER = list(STAGES.keys())

# Per-stage I/O map — the inputs the stage reads + the outputs it writes.
# Glob patterns are evaluated relative to REPO_ROOT.  A stage is considered
# "fresh" if every input is older than every output AND the stage's own
# source file hasn't changed since the last successful run.
#
# Stages with no entry here NEVER skip (we don't know what they touch).
# That's the safe default — better to redo work than silently use stale
# outputs.  Add an entry when you're confident in the I/O contract.
STAGE_IO: dict[str, dict[str, list[str]]] = {
    "features": {
        "inputs":  ["data/parsed/**/*.parquet", "src/features/**/*.py"],
        "outputs": ["data/features/ip/**/*.parquet"],
    },
    "model": {
        "inputs":  ["data/features/ip/**/*.parquet",
                    "src/models/train_threat_classifier.py"],
        "outputs": ["output/models/threat_classifier/**/model.joblib"],
    },
    "score": {
        "inputs":  ["output/models/threat_classifier/**/model.joblib",
                    "data/features/ip/**/*.parquet",
                    "src/models/score_threats.py"],
        "outputs": ["output/reports/threat_scores/threat_scores.parquet"],
    },
    "risk": {
        "inputs":  ["output/reports/threat_scores/threat_scores.parquet",
                    "src/risk/compute_risk_score.py"],
        "outputs": ["output/reports/risk_scores/risk_scores.parquet"],
    },
    "actors": {
        "inputs":  ["data/features/ip/**/*.parquet",
                    "src/models/train_actor_clusterer.py"],
        "outputs": ["output/models/actor_clusterer/**/model.joblib",
                    "output/patterns/actor_clusters/assignments.parquet"],
    },
    "mining": {
        "inputs":  ["data/parsed/**/*.parquet",
                    "src/mining/mine_itemsets.py"],
        "outputs": ["output/patterns/itemsets.parquet"],
    },
    "longitudinal": {
        "inputs":  ["data/parsed/**/*.parquet",
                    "src/longitudinal/detect_changepoints.py"],
        "outputs": ["output/patterns/changepoints/ip_changepoints.parquet"],
    },
    "drift": {
        "inputs":  ["data/features/ip/**/*.parquet",
                    "src/models/detect_drift.py"],
        "outputs": ["output/reports/drift/drift.parquet"],
    },
}

# Explicit dependency overrides — used for stages whose I/O contract is
# not (yet) registered in STAGE_IO but which still have a hard ordering
# requirement.  The DAG planner takes the UNION of these edges and the
# edges inferred from STAGE_IO glob overlap.
EXPLICIT_DEPS: dict[str, list[str]] = {
    "features":     ["analyzers"],
    "model":        ["features"],
    "score":        ["model"],
    "risk":         ["score"],
    "dossiers":     ["risk"],
    "mining":       ["features"],
    "promote":      ["mining", "risk"],
    "longitudinal": ["analyzers"],
    # chains/sequences read ip features + risk; without them they exit early
    # or fall back to no-tier filtering.
    "chains":       ["analyzers", "features", "risk"],
    "sequences":    ["analyzers", "features"],
    "coordination": ["analyzers"],
    "actors":       ["features"],
    "drift":        ["features"],
    "rotation":     ["analyzers"],
    "cross_modal":  ["analyzers"],
    "survival":     ["analyzers"],
    "pktanalysis":     ["analyzers"],
    "payloadanalysis": ["analyzers"],
    "pacing":          ["analyzers"],
    "landscape":       ["analyzers"],
    "protocolanomaly": ["analyzers"],
    "isc_compare":     ["analyzers"],
    "nonipproto":      ["analyzers"],
    "aipayloaddecode": ["nonipproto"],
    # asnintel and cidrintel join packets against per-IP features AND
    # the risk-scored IP set (risk tier, threat density, ASN/CIDR rollups).
    "asnintel":        ["analyzers", "features", "risk"],
    "cidrintel":       ["analyzers", "features", "risk"],
    "tooling":         ["analyzers"],
    # actorlink walks the medium+ risk-tier IPs through tooling fingerprints;
    # exits if risk is missing.
    "actorlink":       ["analyzers", "tooling", "risk"],
    "originintel":     ["actorlink"],
    "slowlow":         ["analyzers"],
    "dnstlsintel":     ["analyzers"],
    "selfmimic":       ["analyzers"],
    # correlate reads every per-analyzer parquet + the risk snapshot;
    # depend broadly so it runs after everything it might join against.
    "correlate":       ["risk", "nonipproto", "protocolanomaly",
                        "asnintel", "cidrintel", "tooling", "slowlow",
                        "selfmimic", "isc_compare", "coordination",
                        "chains"],
    "conclude":        ["correlate"],
    # adversarysim consults other analyzers' outputs for coverage scoring;
    # depending on a broad set of stages keeps it last among siblings.
    "adversarysim":    ["slowlow", "dnstlsintel", "selfmimic",
                        "risk", "report"],
    # The report consumes everything; depend on every stage that has
    # registered outputs.  Anything else just runs before report by
    # virtue of topological order.
    "report":       ["risk", "dossiers", "mining", "promote", "longitudinal",
                     "chains", "sequences", "coordination", "actors",
                     "drift", "rotation", "cross_modal", "survival",
                     "pktanalysis", "payloadanalysis", "pacing", "landscape",
                     "protocolanomaly", "isc_compare", "nonipproto",
                     "aipayloaddecode", "asnintel", "cidrintel", "tooling",
                     "actorlink", "originintel",
                     "slowlow", "dnstlsintel", "selfmimic",
                     "correlate", "conclude"],
    "aireview":     ["report"],
}


def _infer_io_deps() -> dict[str, set[str]]:
    """Build dep edges by looking for output-glob ∩ input-glob overlaps."""
    deps: dict[str, set[str]] = {s: set() for s in STAGES}
    out_owner: dict[str, str] = {}
    for s, io in STAGE_IO.items():
        for o in io.get("outputs", []):
            out_owner.setdefault(o, s)
    for s, io in STAGE_IO.items():
        for inp in io.get("inputs", []):
            for o_pat, owner in out_owner.items():
                if owner == s:
                    continue
                # Treat two globs as "overlapping" if the input pattern
                # would match files the output pattern produces.  Cheap
                # approximation: if input prefix is a prefix of output.
                if inp.startswith(o_pat.rstrip("*")) or \
                   o_pat.startswith(inp.rstrip("*")) or \
                   fnmatch.fnmatch(o_pat, inp):
                    deps[s].add(owner)
    return deps


def build_dependency_graph() -> dict[str, set[str]]:
    """Union of explicit + inferred edges. Maps stage -> set(parents)."""
    deps: dict[str, set[str]] = {s: set() for s in STAGES}
    for s, parents in EXPLICIT_DEPS.items():
        deps[s].update(parents)
    inferred = _infer_io_deps()
    for s, parents in inferred.items():
        deps[s].update(parents)
    # Ensure all referenced parents are real stages.
    for s, parents in deps.items():
        deps[s] = {p for p in parents if p in STAGES}
    return deps


def topological_order(deps: dict[str, set[str]],
                      chosen: list[str]) -> list[str]:
    """Kahn's algorithm restricted to the chosen subset.  Raises on cycle."""
    chosen_set = set(chosen)
    in_deg: dict[str, int] = {
        s: sum(1 for p in deps[s] if p in chosen_set) for s in chosen
    }
    ready = [s for s in chosen if in_deg[s] == 0]
    out: list[str] = []
    while ready:
        ready.sort()  # deterministic
        s = ready.pop(0)
        out.append(s)
        for child in chosen:
            if s in deps[child]:
                in_deg[child] -= 1
                if in_deg[child] == 0:
                    ready.append(child)
    if len(out) != len(chosen):
        leftover = [s for s in chosen if s not in out]
        raise RuntimeError(f"cycle in dependency graph involving: {leftover}")
    return out


# Where we cache freshness state.
_FRESH_CACHE = REPO_ROOT / ".evolve" / "freshness.json"


def _resolve_globs(patterns: list[str]) -> list[Path]:
    found: list[Path] = []
    for pat in patterns:
        for p in REPO_ROOT.glob(pat):
            if p.is_file():
                found.append(p)
    return found


def _hash_command(cmd: list[str]) -> str:
    """SHA-1 of the command + the source file's mtime.  Changes to the
    stage source (e.g. tuning a CLI default) invalidate freshness."""
    h = hashlib.sha1()
    h.update("\0".join(cmd).encode())
    # The first arg after PY is always the stage's source file.
    if len(cmd) >= 2:
        src = Path(cmd[1])
        if src.is_file():
            h.update(str(src.stat().st_mtime_ns).encode())
    return h.hexdigest()


def _load_cache() -> dict:
    if not _FRESH_CACHE.exists():
        return {}
    try:
        return json.loads(_FRESH_CACHE.read_text())
    except json.JSONDecodeError:
        return {}


def _save_cache(c: dict) -> None:
    _FRESH_CACHE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _FRESH_CACHE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(c, indent=2))
    tmp.replace(_FRESH_CACHE)


def is_fresh(name: str, cmd: list[str], cache: dict) -> tuple[bool, str]:
    """Decide whether a stage can be skipped.  Returns (fresh, reason)."""
    io = STAGE_IO.get(name)
    if io is None:
        return False, "no I/O contract registered"
    cached = cache.get(name)
    if not cached:
        return False, "never run successfully"
    if cached.get("cmd_hash") != _hash_command(cmd):
        return False, "command or source changed since last run"
    inputs = _resolve_globs(io.get("inputs", []))
    outputs = _resolve_globs(io.get("outputs", []))
    if not outputs:
        return False, "expected outputs missing"
    if not inputs:
        # No inputs configured -> can't determine staleness; safest to rerun.
        return False, "no inputs found to compare against"
    newest_in = max(p.stat().st_mtime_ns for p in inputs)
    oldest_out = min(p.stat().st_mtime_ns for p in outputs)
    if newest_in > oldest_out:
        return False, "inputs are newer than outputs"
    return True, "outputs newer than inputs"


_CACHE_LOCK = threading.Lock()


def run_stage(name: str, cache: dict, force: bool,
              no_cache: bool) -> tuple[bool, bool]:
    """Run a single stage. Returns (success, skipped)."""
    cmd = [str(PY)] + STAGES[name]
    if not force:
        fresh, why = is_fresh(name, cmd, cache)
        if fresh:
            print(f"[evolve] STAGE: {name} -- skipped ({why})",
                  file=sys.stderr)
            return True, True
    print(f"\n{'='*60}\n[evolve] STAGE: {name}\n{'='*60}", file=sys.stderr)
    t0 = time.time()
    r = subprocess.run(cmd, cwd=REPO_ROOT)
    elapsed = time.time() - t0
    if r.returncode != 0:
        print(f"[evolve] {name} FAILED (exit {r.returncode}, {elapsed:.1f}s)",
              file=sys.stderr)
        return False, False
    print(f"[evolve] {name} ok ({elapsed:.1f}s)", file=sys.stderr)
    if not no_cache and name in STAGE_IO:
        with _CACHE_LOCK:
            cache[name] = {
                "cmd_hash": _hash_command(cmd),
                "ran_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "elapsed_sec": elapsed,
            }
            _save_cache(cache)
    return True, False


def run_dag(chosen: list[str], deps: dict[str, set[str]],
            cache: dict, force: bool, no_cache: bool,
            workers: int) -> tuple[int, int, int]:
    """DAG-aware runner.  Returns (passed, skipped, failed)."""
    chosen_set = set(chosen)
    # Filter deps to chosen subset (an excluded parent doesn't block).
    remaining: dict[str, set[str]] = {
        s: {p for p in deps[s] if p in chosen_set} for s in chosen
    }
    passed = skipped = failed = 0
    failed_stages: set[str] = set()
    in_flight: dict[Future, str] = {}
    completed: set[str] = set()

    def can_launch(s: str) -> bool:
        return (s not in completed and s not in in_flight.values()
                and not remaining[s])

    with ProcessPoolExecutor(max_workers=workers) as pool:
        while len(completed) + len(failed_stages) < len(chosen):
            # Launch every currently-ready stage, up to the pool size.
            ready_now = sorted(s for s in chosen if can_launch(s))
            for s in ready_now:
                # Skip if any parent failed -> mark as failed without running.
                parent_fail = bool(set(deps[s]) & failed_stages)
                if parent_fail:
                    print(f"[evolve] STAGE: {s} -- aborted "
                          f"(upstream failure)", file=sys.stderr)
                    failed_stages.add(s)
                    failed += 1
                    for other in chosen:
                        remaining[other].discard(s)
                    continue
                fut = pool.submit(run_stage, s, cache, force, no_cache)
                in_flight[fut] = s
            if not in_flight:
                # Nothing to launch, nothing in flight -> we'd loop forever.
                missing = [s for s in chosen
                           if s not in completed and s not in failed_stages]
                print(f"[evolve] DAG deadlock; abandoning: {missing}",
                      file=sys.stderr)
                for s in missing:
                    failed_stages.add(s)
                    failed += 1
                break
            done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
            for fut in done:
                s = in_flight.pop(fut)
                try:
                    ok, was_skipped = fut.result()
                except Exception as e:
                    print(f"[evolve] {s} crashed: {e}", file=sys.stderr)
                    ok, was_skipped = False, False
                if ok and was_skipped:
                    skipped += 1
                    completed.add(s)
                elif ok:
                    passed += 1
                    completed.add(s)
                else:
                    failed += 1
                    failed_stages.add(s)
                for child in chosen:
                    remaining[child].discard(s)
    return passed, skipped, failed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stages", nargs="*", help="Specific stages (default: all)")
    ap.add_argument("--skip", nargs="*", default=[], help="Stages to skip")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="Bypass the freshness cache; rerun even if outputs "
                         "look up-to-date.")
    ap.add_argument("--no-cache", action="store_true",
                    help="Do not read OR write the freshness cache. Useful "
                         "for one-off debugging runs.")
    ap.add_argument("--parallel", type=int, default=1, metavar="N",
                    help="Run independent stages on up to N worker "
                         "processes via the DAG planner. N=1 (default) "
                         "preserves the legacy sequential behavior. "
                         "Stage dependencies are computed from STAGE_IO + "
                         "EXPLICIT_DEPS.")
    ap.add_argument("--show-dag", action="store_true",
                    help="Print the computed dependency graph and exit.")
    args = ap.parse_args()

    if args.list:
        for s in ORDER:
            io = STAGE_IO.get(s)
            mark = " [skip-if-fresh]" if io else ""
            print(f"{s}{mark}")
        return 0

    if args.show_dag:
        deps = build_dependency_graph()
        for s in ORDER:
            parents = sorted(deps[s])
            print(f"{s} <- {', '.join(parents) if parents else '(none)'}")
        return 0

    chosen = args.stages or ORDER
    bad = [s for s in chosen if s not in STAGES]
    if bad:
        print(f"Unknown stages: {bad}\nKnown: {ORDER}", file=sys.stderr)
        return 2

    chosen = [s for s in chosen if s not in args.skip]
    # Topological order so even sequential runs respect the DAG.
    deps = build_dependency_graph()
    try:
        chosen = topological_order(deps, chosen)
    except RuntimeError as e:
        print(f"[evolve] {e}", file=sys.stderr)
        return 2
    print(f"[evolve] running stages (topo order): {chosen}", file=sys.stderr)

    cache = {} if args.no_cache else _load_cache()
    t0 = time.time()
    if args.parallel and args.parallel > 1:
        passed, skipped, failed = run_dag(
            chosen, deps, cache, args.force, args.no_cache, args.parallel,
        )
    else:
        passed = failed = skipped = 0
        failed_stages: set[str] = set()
        for s in chosen:
            if set(deps[s]) & failed_stages:
                print(f"[evolve] STAGE: {s} -- aborted (upstream failure)",
                      file=sys.stderr)
                failed += 1
                failed_stages.add(s)
                continue
            ok, was_skipped = run_stage(s, cache, args.force, args.no_cache)
            if ok and was_skipped:
                skipped += 1
            elif ok:
                passed += 1
            else:
                failed += 1
                failed_stages.add(s)
    elapsed = time.time() - t0
    print(f"\n[evolve] done: {passed} ran, {skipped} skipped, "
          f"{failed} failed in {elapsed:.0f}s",
          file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

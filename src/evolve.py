#!/usr/bin/env python3
"""
evolve — orchestrator for the SensorGrind_AI v2 learn-and-evolve loop.

Sequence of stages (each runnable independently):

  0. parse         — raw sensor log -> parquet tables (parser.py); runs only
                     with --input, otherwise the existing parquet is used
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
  python evolve.py --input LOG      # parse LOG first (gzip file, ASCII file,
                                    # or folder) and give it to the other
                                    # raw-log stage (nonipproto); without it
                                    # both are skipped
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import hashlib
import json
import os
import signal
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
    # raw sensor log -> output/parquet/{packets,payload_blobs,l7_events,iocs}
    "parse":        [str(SRC / "parser.py")],
    "analyzers":    [str(SRC / "sgquery.py")],
    # derived packets layout clustered by source ASN/CIDR/IP (see
    # cluster_packets.py); built once per parse, consumers read bounded windows
    "cluster":      [str(SRC / "cluster_packets.py")],
    # --- v3.3 sensor-off + clock-run mask for stateful detectors ---
    "sensormask":   [str(SRC / "sensormask.py")],
    # --- v3.4 neuromorphic per-source scores (LIF/ALIF bank; ARCHITECTURE §9.4)
    "neuro":        [str(SRC / "neuro.py")],
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
    # --- v2.7 chain-fingerprint (packet choreography) per ListonCon 2023 ---
    "chainfp":       [str(SRC / "chainfp.py")],
    # --- v2.8 fused multi-dimensional cluster fingerprint (adaptive episodes) ---
    "compositeprint": [str(SRC / "compositeprint.py")],
    # --- v2.9 campaign migration map (fingerprint rotation across ASN/CIDR/IP) ---
    "campaignmigration": [str(SRC / "campaignmigration.py")],
    # --- v3.1 representation-based HTTP payload templates (Track B) ---
    "httppatterns": [str(SRC / "httppatterns.py")],
    # --- v2.6 cross-analyzer correlator + AI-written conclusions ---
    "correlate":    [str(SRC / "conclusions" / "correlate.py")],
    # --- v3.2 KG-lite: fuse findings into threat storylines (Track C) ---
    "kg":           [str(SRC / "conclusions" / "graph.py")],
    # deterministic, fact-based verdict per finding (no LLM)
    "verdict":      [str(SRC / "conclusions" / "verdict.py")],
    # LLM narratives: paid API calls, so opt-in (see OPT_IN)
    "conclude":     [str(SRC / "conclusions" / "synthesize.py")],
    "report":       [str(SRC / "report" / "comprehensive_report.py")],
    # --- v2.4 cross-AI review of the tool itself ---
    "aireview":     [str(SRC / "aireview.py")],
    # --- v3.0 quantitative baseline metrics (coverage/health + precision) ---
    "metrics":      [str(SRC / "bench" / "compute_metrics.py")],
}
ORDER = list(STAGES.keys())
# Stages that run only when named on the command line, never in a default
# (all-stages) run.  conclude makes paid LLM calls.
OPT_IN = {"conclude"}

# Stages that read the raw sensor log rather than the parquet tables.  They
# get evolve's --input appended; without --input they are skipped.
RAW_INPUT_STAGES = {"parse", "nonipproto"}

# Per-stage I/O map — the inputs the stage reads + the outputs it writes.
# Glob patterns are evaluated relative to REPO_ROOT.  A stage is considered
# "fresh" if every input is older than every output AND the stage's own
# source file hasn't changed since the last successful run.
#
# Stages with no entry here NEVER skip (we don't know what they touch).
# That's the safe default — better to redo work than silently use stale
# outputs.  Add an entry when you're confident in the I/O contract.
_ANALYZERS = (
    "benignfilter", "ja4plus", "fingerprint", "portscans", "droppers",
    "rdpbrute", "tlsintel", "probesigs", "scannerintel", "campaign",
    "botnetcls", "timing", "workhours", "emergence", "ecodanom",
    "trafficprint", "cveseries", "clusterxref", "attackmap")

STAGE_IO: dict[str, dict[str, list[str]]] = {
    # The raw --input log is added to these inputs at run time (is_fresh).
    "parse": {
        "inputs":  ["src/parser.py", "src/sg/sensorlog.py"],
        "outputs": ["output/parquet/packets/**/*.parquet",
                    "output/parquet/payload_blobs/**/*.parquet",
                    "output/parquet/l7_events/**/*.parquet",
                    "output/parquet/iocs/**/*.parquet"],
    },
    # sgquery runs every module in its ANALYZER_ORDER; each reads the parsed
    # tables (some also GeoLite) and writes output/reports/<name>/<name>.*.
    # A new analyzer must be added to both lists.
    "analyzers": {
        "inputs":  ["output/parquet/packets/**/*.parquet",
                    "output/parquet/payload_blobs/**/*.parquet",
                    "output/parquet/l7_events/**/*.parquet",
                    "output/parquet/iocs/**/*.parquet",
                    "GeoLite/**/*.mmdb",
                    "src/sgquery.py", "src/sg/lib.py"]
                   + [f"src/{m}.py" for m in _ANALYZERS],
        "outputs": [f"output/reports/{m}/{m}.parquet" for m in _ANALYZERS],
    },
    "chainfp": {
        "inputs":  ["output/parquet/packets/**/*.parquet",
                    "output/parquet/packets_clustered/**/*.parquet",
                    "src/chainfp.py", "src/sg/lib.py"],
        "outputs": ["output/reports/chainfp/chainfp.parquet",
                    "output/reports/chainfp/window_snr.parquet",
                    "output/reports/chainfp/chainfp_timed.parquet",
                    "output/reports/chainfp/window_snr_timed.parquet"],
    },
    "cluster": {
        "inputs":  ["output/parquet/packets/**/*.parquet",
                    "output/parquet/l7_events/**/*.parquet",
                    "output/parquet/iocs/**/*.parquet",
                    "src/cluster_packets.py"],
        "outputs": ["output/parquet/packets_clustered/**/*.parquet",
                    "output/parquet/l7_events_clustered/**/*.parquet",
                    "output/parquet/iocs_clustered/**/*.parquet"],
    },
    "sensormask": {
        "inputs":  ["output/parquet/packets/**/*.parquet",
                    "output/reports/clock_skew/clock_runs.parquet",
                    "src/sensormask.py"],
        "outputs": ["output/reports/sensormask/sensormask.parquet"],
    },
    "neuro": {
        "inputs":  ["output/parquet/packets/**/*.parquet",
                    "output/reports/sensormask/sensormask.parquet",
                    "output/reports/arrival_eval/arrival_scores_full.parquet",
                    "src/neuro.py", "src/sg/lif.py", "src/bench/lif_eval.py",
                    "src/sg/hdc.py", "src/sg/hdc_gpu.py", "src/bench/hdc_eval.py",
                    "src/chainfp.py", "src/sg/context.py",
                    "output/reports/benignfilter/benignfilter.parquet"],
        # the per-day cache output/.neuro_cache/ stays out of this glob
        # (rule 3 of ARCHITECTURE §9.3)
        "outputs": ["output/reports/neuro/neuro.parquet",
                    "output/reports/neuro/neuro_days.parquet",
                    "output/reports/neuro/neuro_hdc_days.parquet"],
    },
    "features": {
        "inputs":  ["output/parquet/packets/**/*.parquet",
                    "output/parquet/l7_events/**/*.parquet",
                    "output/parquet/iocs/**/*.parquet",
                    "src/features/**/*.py"],
        "outputs": ["output/features/ip/**/*.parquet"],
    },
    "model": {
        "inputs":  ["output/features/ip/**/*.parquet",
                    "src/models/train_threat_classifier.py"],
        "outputs": ["output/models/threat_classifier/**/model.joblib"],
    },
    "score": {
        "inputs":  ["output/models/threat_classifier/**/model.joblib",
                    "output/features/ip/**/*.parquet",
                    "src/models/score_threats.py"],
        "outputs": ["output/risk/threat_scores/scores_*.parquet"],
    },
    "risk": {
        "inputs":  ["output/risk/threat_scores/scores_*.parquet",
                    "src/risk/compute_risk_score.py"],
        "outputs": ["output/risk/ip_risk/**/risk.parquet"],
    },
    "actors": {
        "inputs":  ["output/features/ip/**/*.parquet",
                    "src/models/train_actor_clusterer.py"],
        "outputs": ["output/models/actor_clusterer/**/model.joblib",
                    "output/patterns/actor_clusters/assignments.parquet"],
    },
    "mining": {
        "inputs":  ["output/parquet/packets/**/*.parquet",
                    "src/mining/mine_itemsets.py"],
        "outputs": ["output/patterns/itemsets.parquet"],
    },
    "longitudinal": {
        "inputs":  ["output/parquet/packets/**/*.parquet",
                    "src/longitudinal/detect_changepoints.py"],
        "outputs": ["output/patterns/changepoints/ip_changepoints.parquet"],
    },
    "drift": {
        "inputs":  ["output/features/ip/**/*.parquet",
                    "src/models/detect_drift.py"],
        "outputs": ["output/patterns/drift/drift.parquet"],
    },
    "compositeprint": {
        "inputs":  ["output/parquet/packets/**/*.parquet",
                    "output/reports/ja4plus/ja4plus.parquet",
                    "src/compositeprint.py"],
        "outputs": ["output/reports/compositeprint/composite.parquet"],
    },
    "campaignmigration": {
        "inputs":  ["output/reports/compositeprint/composite.parquet",
                    "output/reports/compositeprint/clusters.parquet",
                    "src/campaignmigration.py"],
        "outputs": ["output/reports/campaignmigration/migration.parquet"],
    },
    "httppatterns": {
        "inputs":  ["output/parquet/payload_blobs/**/*.parquet",
                    "src/httppatterns.py"],
        "outputs": ["output/reports/http_patterns/http_patterns.parquet"],
    },
    "kg": {
        "inputs":  ["output/conclusions/findings.parquet",
                    "output/conclusions/finding_members.parquet",
                    "src/conclusions/graph.py"],
        "outputs": ["output/conclusions/storylines/storylines.parquet"],
    },
}

# Explicit dependency overrides — used for stages whose I/O contract is
# not (yet) registered in STAGE_IO but which still have a hard ordering
# requirement.  The DAG planner takes the UNION of these edges and the
# edges inferred from STAGE_IO glob overlap.
EXPLICIT_DEPS: dict[str, list[str]] = {
    # cluster reads raw packets (not analyzer outputs), so this edge is purely
    # for scheduling: it keeps the two heaviest DuckDB stages from running
    # concurrently in --parallel mode (memory pressure).
    "cluster":      ["analyzers"],
    # neuro reads packets + sensormask; the analyzers/cluster/chainfp edges
    # are for scheduling (memory).  features joins neuro.parquet.
    "neuro":        ["analyzers", "cluster", "chainfp", "sensormask"],
    "features":     ["analyzers", "cluster", "neuro"],
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
    "asnintel":        ["analyzers", "features", "risk", "cluster"],
    "cidrintel":       ["analyzers", "features", "risk"],
    "tooling":         ["analyzers"],
    # actorlink walks the medium+ risk-tier IPs through tooling fingerprints;
    # exits if risk is missing.
    "actorlink":       ["analyzers", "tooling", "risk", "cluster",
                        "compositeprint"],
    "originintel":     ["actorlink"],
    "slowlow":         ["analyzers"],
    "dnstlsintel":     ["analyzers"],
    "selfmimic":       ["analyzers"],
    # chainfp reads packets parquet directly; the cluster edge is purely for
    # scheduling -- it keeps chainfp's heavy DuckDB aggregate from running
    # concurrently with the cluster sort in --parallel mode (memory).
    "chainfp":         ["analyzers", "cluster"],
    # compositeprint fuses chainfp's adaptive sequence/tempo with the per-IP
    # stack/app/payload fingerprints; analyzers produces ja4plus, chainfp the
    # session grammar it reuses, cluster the edge is for scheduling (memory).
    "compositeprint":  ["analyzers", "cluster", "chainfp"],
    # campaignmigration maps compositeprint fingerprints rotating across ASNs
    # over time; asnintel supplies ASN org labels for the collaboration graph.
    "campaignmigration": ["compositeprint", "asnintel"],
    # httppatterns clusters raw HTTP payload_blobs; the analyzers edge is for
    # scheduling (keep its sklearn/hdbscan job off the heaviest DuckDB stages).
    "httppatterns":    ["analyzers"],
    # correlate reads every per-analyzer parquet + the risk snapshot;
    # depend broadly so it runs after everything it might join against.
    "correlate":       ["risk", "nonipproto", "protocolanomaly",
                        "asnintel", "cidrintel", "tooling", "slowlow",
                        "selfmimic", "isc_compare", "coordination",
                        "chains", "chainfp", "compositeprint",
                        "campaignmigration", "neuro"],
    # kg fuses the correlator's findings into storylines; conclude then narrates
    # both the per-finding cards and the multi-finding storylines.
    "kg":              ["correlate"],
    # verdict reads the findings + members, benignfilter (analyzers) and risk.
    "verdict":         ["correlate", "analyzers", "risk"],
    "conclude":        ["correlate", "kg"],
    # adversarysim consults other analyzers' outputs for coverage scoring;
    # depending on a broad set of stages keeps it last among siblings.
    "adversarysim":    ["slowlow", "dnstlsintel", "selfmimic",
                        "risk", "report"],
    # The report consumes everything; depend on every stage that has
    # registered outputs.  Anything else just runs before report by
    # virtue of topological order.
    "report":       ["risk", "neuro", "dossiers", "mining", "promote", "longitudinal",
                     "chains", "sequences", "coordination", "actors",
                     "drift", "rotation", "cross_modal", "survival",
                     "pktanalysis", "payloadanalysis", "pacing", "landscape",
                     "protocolanomaly", "isc_compare", "nonipproto",
                     "aipayloaddecode", "asnintel", "cidrintel", "tooling",
                     "actorlink", "originintel",
                     "slowlow", "dnstlsintel", "selfmimic",
                     "chainfp", "compositeprint", "campaignmigration",
                     "httppatterns", "correlate", "kg", "verdict", "conclude"],
    "aireview":     ["report"],
    # metrics reads findings (conclude), storylines (kg), risk, and analyzer
    # reports (trafficprint, attackmap, httppatterns); depend on producers.
    "metrics":      ["conclude", "verdict", "kg", "risk", "analyzers", "httppatterns"],
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
    # Everything downstream reads the parsed tables: every otherwise-root
    # stage waits for parse (a no-op skip when --input is not given).
    for s in STAGES:
        if s != "parse" and not deps[s]:
            deps[s].add("parse")
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

# Per-stage output is tee'd to a clean log file here, so the real error is
# recoverable even when parallel stages interleave on the console.
LOG_DIR = REPO_ROOT / ".evolve" / "logs"

# Every run also auto-captures the full combined console output here, so a run
# is never lost just because it wasn't manually `| tee`'d.
RUN_LOG_DIR = REPO_ROOT / "output" / "logs"


class _Tee:
    """Duplicate writes to several streams (e.g. real stderr + a run log).

    Used to capture the whole run to a file without the caller having to
    redirect.  Best-effort: a write that fails on one stream still reaches
    the others, so a full disk on the log file never crashes the pipeline.
    """

    def __init__(self, *streams):
        self._streams = [s for s in streams if s is not None]

    def write(self, data):
        for s in self._streams:
            try:
                s.write(data)
            except (OSError, ValueError):
                pass
        return len(data)

    def flush(self):
        for s in self._streams:
            try:
                s.flush()
            except (OSError, ValueError):
                pass

    def isatty(self):
        # Preserve TTY semantics of the primary (first) stream.
        return bool(self._streams) and getattr(
            self._streams[0], "isatty", lambda: False)()


def _stage_log(name: str) -> Path:
    return LOG_DIR / f"{name}.log"


def _tail(path: Path, n: int = 20) -> list[str]:
    try:
        return path.read_text(errors="replace").splitlines()[-n:]
    except OSError:
        return []


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


def _raw_input_files(raw_input: str | None) -> list[Path]:
    if not raw_input:
        return []
    p = Path(raw_input)
    if p.is_dir():
        return [f for f in p.iterdir() if f.is_file()]
    return [p] if p.is_file() else []


def is_fresh(name: str, cmd: list[str], cache: dict,
             raw_input: str | None = None) -> tuple[bool, str]:
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
    if name in RAW_INPUT_STAGES:
        inputs += _raw_input_files(raw_input)
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

# --- memory governance (Linux /proc-based; psutil not required) ----------
# A stage that misbehaves on memory gets stopped gracefully and logged
# BEFORE the kernel OOM-killer sends an opaque SIGKILL.  Tunable via env:
#   SG_MEM_GUARD=0        disable the watchdog entirely
#   SG_MEM_FLOOR_MB       stop a stage when system MemAvailable drops below
#                         this (default 2048) AND the stage is a memory hog
#   SG_MEM_BLAME_MB       only blame/stop stages whose own RSS exceeds this
#                         (default 2048) -- don't kill small stages
#   SG_MEM_HARD_CAP_MB    hard per-stage RSS ceiling (default 0 = off)
#   SG_MEM_SAMPLE_SEC     sampling cadence (default 5)
#   SG_MEM_LOG_SEC        telemetry log cadence (default 30)
try:
    _PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024
except (ValueError, OSError, AttributeError):
    _PAGE_KB = 4


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _mem_available_mb() -> int | None:
    """System MemAvailable in MiB, or None if /proc isn't readable."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError):
        return None
    return None


def _proc_rss_mb(pid: int) -> int | None:
    """Resident set size of ``pid`` in MiB (DuckDB's threads are in-process,
    so this covers them), or None if the process/proc isn't readable."""
    try:
        with open(f"/proc/{pid}/statm") as f:
            resident_pages = int(f.read().split()[1])
        return resident_pages * _PAGE_KB // 1024
    except (OSError, ValueError):
        return None


class MemoryWatchdog(threading.Thread):
    """Samples a stage's RSS + system available memory, logs telemetry, and
    stops the stage gracefully before it can trigger the OOM-killer."""

    def __init__(self, pid: int, name: str):
        super().__init__(daemon=True)
        self.pid = pid
        self.name = name
        self.floor_mb = _env_int("SG_MEM_FLOOR_MB", 2048)
        self.blame_mb = _env_int("SG_MEM_BLAME_MB", 2048)
        self.hard_cap_mb = _env_int("SG_MEM_HARD_CAP_MB", 0)
        self.sample_sec = max(1, _env_int("SG_MEM_SAMPLE_SEC", 5))
        self.log_sec = max(1, _env_int("SG_MEM_LOG_SEC", 30))
        self._stop_evt = threading.Event()
        self.killed = False
        self.reason = ""

    def run(self) -> None:
        if not Path("/proc").is_dir():
            return
        last_log = 0.0
        while not self._stop_evt.wait(self.sample_sec):
            rss = _proc_rss_mb(self.pid)
            avail = _mem_available_mb()
            if rss is None:
                continue
            now = time.monotonic()
            if now - last_log >= self.log_sec:
                a = f"{avail/1024:.1f}G" if avail is not None else "?"
                print(f"[evolve] mem: stage={self.name} "
                      f"rss={rss/1024:.1f}G sys_avail={a}", file=sys.stderr)
                last_log = now
            reason = ""
            if self.hard_cap_mb and rss > self.hard_cap_mb:
                reason = (f"stage RSS {rss/1024:.1f}G exceeded hard cap "
                          f"{self.hard_cap_mb/1024:.1f}G")
            elif (avail is not None and avail < self.floor_mb
                  and rss > self.blame_mb):
                reason = (f"system memory low (avail {avail/1024:.1f}G < floor "
                          f"{self.floor_mb/1024:.1f}G) while stage holds "
                          f"{rss/1024:.1f}G")
            if reason:
                self.killed = True
                self.reason = reason
                print(f"[evolve] MEMORY GUARD: stopping stage '{self.name}' "
                      f"-- {reason}", file=sys.stderr)
                try:
                    os.kill(self.pid, signal.SIGTERM)
                except OSError:
                    pass
                # Give it a few seconds to exit cleanly, then SIGKILL.
                if not self._stop_evt.wait(8):
                    try:
                        os.kill(self.pid, signal.SIGKILL)
                    except OSError:
                        pass
                return

    def stop(self) -> None:
        self._stop_evt.set()


def _terminate(proc: subprocess.Popen, grace: float = 10.0) -> None:
    """Best-effort graceful stop of a stage's child process.

    On Ctrl+C the child shares our process group and has already received
    the same SIGINT, so first give it ``grace`` seconds to exit on its own,
    then escalate SIGTERM -> SIGKILL so nothing is left running.
    """
    if proc.poll() is not None:
        return
    try:
        proc.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass
    except (OSError, ValueError):
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    except (OSError, ValueError):
        return
    try:
        proc.kill()
        proc.wait(timeout=5)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass


def run_stage(name: str, cache: dict, force: bool,
              no_cache: bool, raw_input: str | None = None
              ) -> tuple[bool, bool, str]:
    """Run a single stage. Returns (success, skipped, detail).

    ``detail`` is empty on success/skip and a short failure reason
    (e.g. ``"exit 1"``) otherwise.  The stage's combined stdout+stderr is
    tee'd to ``.evolve/logs/<name>.log`` so the real error is recoverable
    even when parallel stages interleave on the console.
    """
    cmd = [str(PY)] + STAGES[name]
    if name in RAW_INPUT_STAGES:
        if not raw_input:
            print(f"[evolve] STAGE: {name} -- skipped (needs the raw sensor "
                  f"log; pass --input)", file=sys.stderr)
            return True, True, ""
        cmd.append(raw_input)
    if not force:
        fresh, why = is_fresh(name, cmd, cache, raw_input)
        if fresh:
            print(f"[evolve] STAGE: {name} -- skipped ({why})",
                  file=sys.stderr)
            return True, True, ""
    print(f"\n{'='*60}\n[evolve] STAGE: {name}\n{'='*60}", file=sys.stderr)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = _stage_log(name)
    t0 = time.time()
    wd: MemoryWatchdog | None = None
    try:
        with open(log_path, "w", buffering=1) as logf:  # line-buffered
            proc = subprocess.Popen(
                cmd, cwd=REPO_ROOT,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            if os.environ.get("SG_MEM_GUARD", "1") != "0":
                wd = MemoryWatchdog(proc.pid, name)
                wd.start()
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    sys.stderr.write(line)
                    logf.write(line)
                proc.wait()
            except KeyboardInterrupt:
                # Ctrl+C: stop the child cleanly, then propagate so the
                # orchestrator can shut the whole run down gracefully.
                print(f"\n[evolve] {name} interrupted -- stopping child...",
                      file=sys.stderr)
                _terminate(proc)
                logf.flush()
                raise
            finally:
                if wd is not None:
                    wd.stop()
                    wd.join(timeout=2)
        rc = proc.returncode
    except OSError as e:
        print(f"[evolve] {name} could not launch: {e}", file=sys.stderr)
        return False, False, f"launch error: {e}"
    elapsed = time.time() - t0
    if wd is not None and wd.killed:
        print(f"[evolve] {name} STOPPED by memory guard ({elapsed:.1f}s) "
              f"-- {wd.reason} -- full log: {log_path}", file=sys.stderr)
        return False, False, f"stopped: memory guard ({wd.reason})"
    if rc != 0:
        print(f"[evolve] {name} FAILED (exit {rc}, {elapsed:.1f}s) "
              f"-- full log: {log_path}", file=sys.stderr)
        return False, False, f"exit {rc}"
    print(f"[evolve] {name} ok ({elapsed:.1f}s)", file=sys.stderr)
    if not no_cache and name in STAGE_IO:
        with _CACHE_LOCK:
            cache[name] = {
                "cmd_hash": _hash_command(cmd),
                "ran_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "elapsed_sec": elapsed,
            }
            _save_cache(cache)
    return True, False, ""


def run_dag(chosen: list[str], deps: dict[str, set[str]],
            cache: dict, force: bool, no_cache: bool,
            workers: int, raw_input: str | None = None
            ) -> tuple[int, int, int, set[str],
                                   dict[str, str], bool]:
    """DAG-aware runner.

    Returns (passed, skipped, failed, failed_stages, failure_reason,
    interrupted).  ``failure_reason`` maps each failed stage to a short
    cause string; ``interrupted`` is True if the run was stopped by Ctrl+C.
    """
    chosen_set = set(chosen)
    # Filter deps to chosen subset (an excluded parent doesn't block).
    remaining: dict[str, set[str]] = {
        s: {p for p in deps[s] if p in chosen_set} for s in chosen
    }
    passed = skipped = failed = 0
    failed_stages: set[str] = set()
    failure_reason: dict[str, str] = {}
    in_flight: dict[Future, str] = {}
    completed: set[str] = set()
    interrupted = False

    def can_launch(s: str) -> bool:
        # NOTE: must exclude failed_stages -- otherwise a stage that fails
        # (and isn't in `completed`) stays launchable and gets relaunched
        # every loop iteration, looping forever on a deterministic failure.
        return (s not in completed and s not in failed_stages
                and s not in in_flight.values() and not remaining[s])

    pool = ProcessPoolExecutor(max_workers=workers)
    try:
        while len(completed) + len(failed_stages) < len(chosen):
            # Launch every currently-ready stage, up to the pool size.
            ready_now = sorted(s for s in chosen if can_launch(s))
            for s in ready_now:
                # Skip if any parent failed -> mark as failed without running.
                bad_parents = sorted(set(deps[s]) & failed_stages)
                if bad_parents:
                    print(f"[evolve] STAGE: {s} -- aborted "
                          f"(blocked by failed: {', '.join(bad_parents)})",
                          file=sys.stderr)
                    failed_stages.add(s)
                    failure_reason[s] = (
                        f"upstream failure: {', '.join(bad_parents)}")
                    failed += 1
                    for other in chosen:
                        remaining[other].discard(s)
                    continue
                fut = pool.submit(run_stage, s, cache, force, no_cache,
                                  raw_input)
                in_flight[fut] = s
            if not in_flight:
                # Nothing to launch, nothing in flight -> we'd loop forever.
                missing = [s for s in chosen
                           if s not in completed and s not in failed_stages]
                print(f"[evolve] DAG deadlock; abandoning: {missing}",
                      file=sys.stderr)
                for s in missing:
                    failed_stages.add(s)
                    failure_reason[s] = "DAG deadlock (unsatisfiable deps)"
                    failed += 1
                break
            done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
            for fut in done:
                s = in_flight.pop(fut)
                try:
                    ok, was_skipped, detail = fut.result()
                except Exception as e:
                    print(f"[evolve] {s} crashed: {e}", file=sys.stderr)
                    ok, was_skipped, detail = False, False, f"crashed: {e}"
                if ok and was_skipped:
                    skipped += 1
                    completed.add(s)
                elif ok:
                    passed += 1
                    completed.add(s)
                else:
                    failed += 1
                    failed_stages.add(s)
                    failure_reason[s] = detail or "failed"
                for child in chosen:
                    remaining[child].discard(s)
    except KeyboardInterrupt:
        interrupted = True
        not_run = [s for s in chosen
                   if s not in completed and s not in failed_stages]
        print(f"\n[evolve] interrupted by user (Ctrl+C) -- cancelling "
              f"{len(not_run)} not-yet-finished stage(s) and stopping "
              f"workers...", file=sys.stderr)
        for s in not_run:
            failed_stages.add(s)
            failure_reason[s] = "interrupted (not finished)"
    finally:
        # Never block waiting on in-flight stages: cancel what's queued and
        # let the workers (which got the same SIGINT) wind down.
        pool.shutdown(wait=False, cancel_futures=True)
    return passed, skipped, failed, failed_stages, failure_reason, interrupted


def _print_failure_summary(failed_stages: set[str],
                           failure_reason: dict[str, str],
                           deps: dict[str, set[str]]) -> None:
    """Separate the stage(s) that actually broke from those merely blocked
    behind them, and show the real error tail for each root cause."""
    # Stages merely cut short by Ctrl+C aren't real failures; the run's
    # "(INTERRUPTED)" banner already covers them, so don't list them here.
    shown = {s for s in failed_stages
             if not failure_reason.get(s, "").startswith("interrupted")}
    if not shown:
        return
    # A root cause is a failed stage none of whose parents also failed.
    roots = sorted(s for s in shown
                   if not (set(deps[s]) & failed_stages))
    cascaded = sorted(shown - set(roots))

    print(f"\n{'='*60}\n[evolve] FAILURE SUMMARY\n{'='*60}", file=sys.stderr)
    print("[evolve] root cause(s) -- these stages actually failed:",
          file=sys.stderr)
    for s in roots:
        print(f"  [FAIL] {s}: {failure_reason.get(s, 'failed')}",
              file=sys.stderr)
        log_path = _stage_log(s)
        tail = _tail(log_path)
        if tail:
            print(f"      --- last {len(tail)} lines of {log_path} ---",
                  file=sys.stderr)
            for ln in tail:
                print(f"      | {ln}", file=sys.stderr)
    if cascaded:
        print("[evolve] not run (blocked by the failure(s) above):",
              file=sys.stderr)
        for s in cascaded:
            bad = sorted(set(deps[s]) & failed_stages)
            print(f"  - {s}  (waiting on: {', '.join(bad)})", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stages", nargs="*",
                    help="Specific stages (default: all except the opt-in "
                         f"stages: {', '.join(sorted(OPT_IN))})")
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
    ap.add_argument("--input", metavar="LOG",
                    help="Raw sensor log for the stages that read it "
                         f"({', '.join(sorted(RAW_INPUT_STAGES))}): a gzip "
                         "file, a plain ASCII file, or a folder of them.  "
                         "Without it those stages are skipped and the "
                         "existing parquet tables are used.")
    ap.add_argument("--show-dag", action="store_true",
                    help="Print the computed dependency graph and exit.")
    ap.add_argument("--no-run-log", action="store_true",
                    help="Do not auto-capture this run to "
                         "output/logs/evolve_<timestamp>.log. By default "
                         "every run is logged there in addition to the "
                         "console, so a run is never lost.")
    args = ap.parse_args()

    raw_input = None
    if args.input:
        in_path = Path(args.input).expanduser().resolve()
        if not in_path.exists():
            print(f"[evolve] input not found: {in_path}", file=sys.stderr)
            return 2
        raw_input = str(in_path)

    if args.list:
        for s in ORDER:
            io = STAGE_IO.get(s)
            mark = " [skip-if-fresh]" if io else ""
            mark += " [opt-in]" if s in OPT_IN else ""
            print(f"{s}{mark}")
        return 0

    if args.show_dag:
        deps = build_dependency_graph()
        for s in ORDER:
            parents = sorted(deps[s])
            print(f"{s} <- {', '.join(parents) if parents else '(none)'}")
        return 0

    # --- auto run log: capture the whole run to a timestamped file so a
    # run is never lost just because it wasn't manually redirected. ---
    orig_stdout, orig_stderr = sys.stdout, sys.stderr
    run_log_fh = None
    if not args.no_run_log:
        try:
            RUN_LOG_DIR.mkdir(parents=True, exist_ok=True)
            stamp = _dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
            run_log_path = RUN_LOG_DIR / f"evolve_{stamp}.log"
            run_log_fh = open(run_log_path, "w", buffering=1)  # line-buffered
            sys.stdout = _Tee(orig_stdout, run_log_fh)
            sys.stderr = _Tee(orig_stderr, run_log_fh)
            print(f"[evolve] run log: {run_log_path}", file=sys.stderr)
        except OSError as e:
            print(f"[evolve] WARNING: could not open run log ({e}); "
                  f"continuing with console output only", file=sys.stderr)
            run_log_fh = None

    try:
        chosen = args.stages or [s for s in ORDER if s not in OPT_IN]
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
        print(f"[evolve] running stages (topo order): {chosen}",
              file=sys.stderr)

        cache = {} if args.no_cache else _load_cache()
        t0 = time.time()
        passed = failed = skipped = 0
        failed_stages: set[str] = set()
        failure_reason: dict[str, str] = {}
        interrupted = False
        try:
            if args.parallel and args.parallel > 1:
                # run_dag handles Ctrl+C internally and reports it back.
                (passed, skipped, failed, failed_stages,
                 failure_reason, interrupted) = run_dag(
                    chosen, deps, cache, args.force, args.no_cache,
                    args.parallel, raw_input,
                )
            else:
                for s in chosen:
                    bad_parents = sorted(set(deps[s]) & failed_stages)
                    if bad_parents:
                        print(f"[evolve] STAGE: {s} -- aborted "
                              f"(blocked by failed: {', '.join(bad_parents)})",
                              file=sys.stderr)
                        failed += 1
                        failed_stages.add(s)
                        failure_reason[s] = (
                            f"upstream failure: {', '.join(bad_parents)}")
                        continue
                    ok, was_skipped, detail = run_stage(
                        s, cache, args.force, args.no_cache, raw_input)
                    if ok and was_skipped:
                        skipped += 1
                    elif ok:
                        passed += 1
                    else:
                        failed += 1
                        failed_stages.add(s)
                        failure_reason[s] = detail or "failed"
        except KeyboardInterrupt:
            interrupted = True
            print("\n[evolve] interrupted by user (Ctrl+C) -- stopping "
                  "after the current stage; partial results kept.",
                  file=sys.stderr)

        elapsed = time.time() - t0
        _print_failure_summary(failed_stages, failure_reason, deps)
        print(f"\n[evolve] done: {passed} ran, {skipped} skipped, "
              f"{failed} failed in {elapsed:.0f}s"
              f"{' (INTERRUPTED)' if interrupted else ''}",
              file=sys.stderr)
        if interrupted:
            return 130  # conventional exit code for SIGINT
        return 1 if failed else 0
    finally:
        # Restore the real streams and flush/close the run log.
        sys.stdout, sys.stderr = orig_stdout, orig_stderr
        if run_log_fh is not None:
            try:
                run_log_fh.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())

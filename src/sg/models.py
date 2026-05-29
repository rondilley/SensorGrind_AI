"""
sg.models — model registry for SensorGrind_AI v2.

Persists trained models as joblib artifacts plus a JSON registry
tracking version, training data range, evaluation metrics, and
the feature set version used.

Layout:
    data/models/
        registry.json
        {model_name}/v{N}/
            model.joblib
            metadata.json
            eval.json     (optional)

The registry is the source of truth for which model is "current" for
each name; scoring scripts load the current entry by default.
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import joblib

from . import lib as _lib

MODELS = _lib.OUTPUT_DIR / "models"
MODELS.mkdir(parents=True, exist_ok=True)
REGISTRY_PATH = MODELS / "registry.json"


@dataclass
class ModelInfo:
    name: str
    version: int
    model_type: str            # e.g. "lightgbm.LGBMClassifier", "hdbscan.HDBSCAN"
    feature_set: str           # e.g. "ip:v1"
    training_rows: int
    training_range: tuple[str, str]  # (since_iso, until_iso)
    trained_at: str
    metrics: dict[str, Any]
    is_current: bool = False


_REGISTRY_LOCK = MODELS / "registry.json.lock"


def _registry_lock():
    """Cross-process file lock for the registry.json read-modify-write
    cycle.  Required because next_version / save_model otherwise race
    against any concurrent training stage and the last writer wins,
    silently losing model entries (real issue flagged by the multi-AI
    architecture review)."""
    import filelock
    return filelock.FileLock(str(_REGISTRY_LOCK), timeout=60)


def _load_registry() -> dict[str, list[dict]]:
    if not REGISTRY_PATH.exists():
        return {}
    try:
        return json.loads(REGISTRY_PATH.read_text())
    except json.JSONDecodeError:
        # Don't blow up the entire pipeline if the registry got corrupted;
        # back it up with a timestamp and start fresh.  Better to leave a
        # forensic copy than to crash silently mid-pipeline.
        import shutil, time as _t
        bak = REGISTRY_PATH.with_suffix(f".json.corrupt.{int(_t.time())}")
        shutil.copy2(REGISTRY_PATH, bak)
        return {}


def _save_registry(reg: dict[str, list[dict]]) -> None:
    tmp = REGISTRY_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(reg, indent=2, default=str))
    tmp.replace(REGISTRY_PATH)


def next_version(name: str) -> int:
    with _registry_lock():
        reg = _load_registry()
        versions = [e["version"] for e in reg.get(name, [])]
        return max(versions, default=0) + 1


def model_dir(name: str, version: int) -> Path:
    return MODELS / name / f"v{version}"


def save_model(name: str, model: Any, info: ModelInfo, make_current: bool = True) -> Path:
    d = model_dir(name, info.version)
    d.mkdir(parents=True, exist_ok=True)
    artifact = d / "model.joblib"
    joblib.dump(model, artifact)
    (d / "metadata.json").write_text(json.dumps(asdict(info), indent=2, default=str))

    # Read-modify-write the global registry under the cross-process lock
    # so concurrent training stages don't lose each other's entries.
    with _registry_lock():
        reg = _load_registry()
        entries = reg.get(name, [])
        if make_current:
            for e in entries:
                e["is_current"] = False
            info.is_current = True
        entries.append({**asdict(info), "artifact": str(artifact)})
        reg[name] = entries
        _save_registry(reg)
    return artifact


def load_current(name: str) -> tuple[Any, ModelInfo] | None:
    reg = _load_registry()
    entries = reg.get(name, [])
    current = [e for e in entries if e.get("is_current")]
    if not current:
        return None
    e = current[0]
    artifact_path = Path(e["artifact"])
    if not artifact_path.exists():
        return None
    model = joblib.load(artifact_path)
    info = ModelInfo(
        name=e["name"], version=e["version"], model_type=e["model_type"],
        feature_set=e["feature_set"], training_rows=e["training_rows"],
        training_range=tuple(e["training_range"]),
        trained_at=e["trained_at"], metrics=e["metrics"],
        is_current=True,
    )
    return model, info


def list_models() -> dict[str, list[ModelInfo]]:
    reg = _load_registry()
    out: dict[str, list[ModelInfo]] = {}
    for name, entries in reg.items():
        out[name] = [ModelInfo(
            name=e["name"], version=e["version"], model_type=e["model_type"],
            feature_set=e["feature_set"], training_rows=e["training_rows"],
            training_range=tuple(e["training_range"]),
            trained_at=e["trained_at"], metrics=e["metrics"],
            is_current=e.get("is_current", False),
        ) for e in entries]
    return out

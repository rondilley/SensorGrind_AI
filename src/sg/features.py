"""
sg.features — feature store for SensorGrind_AI v2.

Daily Parquet snapshots of per-entity feature vectors, partitioned
by date and entity type. Schema versioning lets us evolve features
without breaking already-trained models.

Layout:
    data/features/
        ip/dt=YYYY-MM-DD/v={N}/part-NNNN.parquet
        payload/dt=YYYY-MM-DD/v={N}/part-NNNN.parquet
        campaign/dt=YYYY-MM-DD/v={N}/part-NNNN.parquet

`v=N` reflects the feature builder version. Loading code requests a
specific version; mismatched snapshots are ignored.
"""
from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from . import lib as _lib

FEATURES = _lib.OUTPUT_DIR / "features"
FEATURES.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class FeatureSet:
    """Identifier for a stored feature set."""
    entity: str          # "ip", "payload", "campaign"
    version: int
    snapshot_date: _dt.date


def snapshot_dir(fs: FeatureSet) -> Path:
    return FEATURES / fs.entity / f"dt={fs.snapshot_date.isoformat()}" / f"v={fs.version}"


def write_snapshot(fs: FeatureSet, table: pa.Table, manifest: dict[str, Any] | None = None) -> Path:
    """Atomically write a feature snapshot. Returns the parquet path."""
    out_dir = snapshot_dir(fs)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "part-0000.parquet"
    tmp_path = out_dir / "part-0000.parquet.tmp"
    pq.write_table(table, tmp_path, compression="zstd", compression_level=3)
    tmp_path.replace(out_path)
    if manifest is not None:
        manifest_path = out_dir / "manifest.json"
        full = {
            "entity": fs.entity,
            "version": fs.version,
            "snapshot_date": fs.snapshot_date.isoformat(),
            "row_count": table.num_rows,
            "column_count": table.num_columns,
            "columns": [c.name for c in table.schema],
            "written_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            **manifest,
        }
        manifest_path.write_text(json.dumps(full, indent=2, default=str))
    return out_path


def write_snapshot_stream(fs: FeatureSet, schema: pa.Schema,
                          tables, manifest: dict[str, Any] | None = None
                          ) -> tuple[Path, int]:
    """Atomically write a feature snapshot from a stream of tables.

    ``tables`` is any iterable of ``pa.Table`` (or RecordBatch) chunks, each
    already matching ``schema``.  They are written incrementally so the whole
    feature set never has to exist in memory at once.  Returns
    ``(parquet_path, row_count)``.
    """
    out_dir = snapshot_dir(fs)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "part-0000.parquet"
    tmp_path = out_dir / "part-0000.parquet.tmp"
    row_count = 0
    writer = pq.ParquetWriter(tmp_path, schema, compression="zstd",
                              compression_level=3)
    try:
        for tbl in tables:
            if isinstance(tbl, pa.RecordBatch):
                tbl = pa.Table.from_batches([tbl], schema=schema)
            if tbl.num_rows == 0:
                continue
            writer.write_table(tbl)
            row_count += tbl.num_rows
    finally:
        writer.close()
    tmp_path.replace(out_path)
    if manifest is not None:
        manifest_path = out_dir / "manifest.json"
        full = {
            "entity": fs.entity,
            "version": fs.version,
            "snapshot_date": fs.snapshot_date.isoformat(),
            "row_count": row_count,
            "column_count": len(schema),
            "columns": [f.name for f in schema],
            "written_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            **manifest,
        }
        manifest_path.write_text(json.dumps(full, indent=2, default=str))
    return out_path, row_count


def load_snapshot(fs: FeatureSet) -> pa.Table | None:
    p = snapshot_dir(fs) / "part-0000.parquet"
    if not p.exists():
        return None
    return pq.read_table(p)


def list_snapshots(entity: str, version: int | None = None) -> list[FeatureSet]:
    """Enumerate all snapshots on disk for a given entity (optionally version)."""
    out: list[FeatureSet] = []
    base = FEATURES / entity
    if not base.exists():
        return out
    for dt_dir in sorted(base.glob("dt=*")):
        try:
            d = _dt.date.fromisoformat(dt_dir.name[3:])
        except ValueError:
            continue
        for v_dir in dt_dir.glob("v=*"):
            try:
                v = int(v_dir.name[2:])
            except ValueError:
                continue
            if version is not None and v != version:
                continue
            if (v_dir / "part-0000.parquet").exists():
                out.append(FeatureSet(entity=entity, version=v, snapshot_date=d))
    return out


def latest_snapshot(entity: str, version: int) -> FeatureSet | None:
    snaps = [s for s in list_snapshots(entity, version) if s.version == version]
    if not snaps:
        return None
    snaps.sort(key=lambda s: s.snapshot_date)
    return snaps[-1]


def parquet_glob(entity: str, version: int) -> str:
    """DuckDB-friendly glob over all snapshots of an entity@version."""
    return str(FEATURES / entity / "dt=*" / f"v={version}" / "*.parquet")

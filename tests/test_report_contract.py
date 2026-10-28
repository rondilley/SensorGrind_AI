"""sg.lib.Report + markdown_table contract.

The pipeline's freshness/DAG logic assumes every analyzer always emits a
*valid, readable* Parquet (even with zero rows) plus a sibling .md. A
regression here silently breaks every downstream read_parquet() glob.
"""
from __future__ import annotations

import pyarrow as pa
import pyarrow.parquet as pq

SCHEMA = pa.schema([("technique", pa.string()), ("evidence_count", pa.int64())])


def test_empty_rows_still_write_valid_parquet(tmp_output):
    lib = tmp_output
    rep = lib.Report(name="t_empty", rows=[], schema=SCHEMA, markdown="")
    paths = rep.write()
    assert paths["parquet"].exists() and paths["markdown"].exists()
    # must be a readable Parquet with the declared schema, 0 rows.
    t = pq.read_table(paths["parquet"])
    assert t.num_rows == 0
    assert t.schema.names == ["technique", "evidence_count"]


def test_rows_roundtrip_with_schema(tmp_output):
    lib = tmp_output
    rows = [{"technique": "T1046", "evidence_count": 5},
            {"technique": "T1110", "evidence_count": 9}]
    paths = lib.Report(name="t_rows", rows=rows, schema=SCHEMA).write()
    t = pq.read_table(paths["parquet"])
    assert t.num_rows == 2
    assert t.column("technique").to_pylist() == ["T1046", "T1110"]


def test_write_is_atomic_no_tmp_left_behind(tmp_output):
    lib = tmp_output
    paths = lib.Report(name="t_atomic", rows=[{"technique": "x",
                       "evidence_count": 1}], schema=SCHEMA).write()
    tmp = paths["parquet"].with_suffix(paths["parquet"].suffix + ".tmp")
    assert not tmp.exists(), "atomic write left a .tmp sibling"


def test_accepts_arrow_table_directly(tmp_output):
    lib = tmp_output
    tbl = pa.Table.from_pylist([{"technique": "T1046",
                                 "evidence_count": 3}], schema=SCHEMA)
    paths = lib.Report(name="t_tbl", rows=tbl).write()
    assert pq.read_table(paths["parquet"]).num_rows == 1


def test_markdown_table_escapes_pipes_and_newlines(tmp_output):
    lib = tmp_output
    md = lib.markdown_table([{"a": "x|y", "b": "line1\nline2"}])
    # a literal pipe inside a cell would break the column count if unescaped
    assert "x\\|y" in md
    assert "line1 line2" in md  # newline collapsed to space


def test_markdown_table_empty_is_safe(tmp_output):
    lib = tmp_output
    assert "empty" in lib.markdown_table([]).lower()

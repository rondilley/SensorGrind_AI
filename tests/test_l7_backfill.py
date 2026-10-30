"""l7_backfill.rewrite_file contract: only target rows change, the schema and
the row-group structure stay the same."""
from __future__ import annotations

import pyarrow as pa
import pyarrow.parquet as pq

import l7_backfill


def test_rewrite_file_changes_only_targets(tmp_path):
    a, b = b"\x01" * 32, b"\x02" * 32
    schema = pa.schema([("payload_sha256", pa.binary(32)), ("l7_proto", pa.uint8()),
                        ("src_ip", pa.string())])
    p = tmp_path / "part-0000.parquet"
    with pq.ParquetWriter(p, schema) as w:
        w.write_table(pa.table({"payload_sha256": [a, b], "l7_proto": [0, 0],
                                "src_ip": ["x", "y"]}, schema=schema))
        w.write_table(pa.table({"payload_sha256": [None, a], "l7_proto": [0, 3],
                                "src_ip": ["z", "w"]}, schema=schema))
    path, changed = l7_backfill.rewrite_file(str(p), [a], [12], None)
    assert changed == 2
    pf = pq.ParquetFile(p)
    assert pf.num_row_groups == 2
    assert pf.schema_arrow == schema
    assert pq.read_table(p).column("l7_proto").to_pylist() == [12, 0, 0, 12]
    assert not (tmp_path / "part-0000.parquet.l7tmp").exists()

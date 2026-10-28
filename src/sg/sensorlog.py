"""sensorlog — one reader for every raw honeypot sensor-log input.

``iter_lines(path)`` yields raw syslog lines (bytes, no trailing newline)
from any of:

  * a gzip file           — detected by magic bytes, not by extension;
                            decompressed by ``zcat`` in a child process
  * a plain ASCII file    — e.g. honeypi_logs.py's honeypi_sensor.log
  * a folder              — every gzip / text file directly inside it
                            (not recursive: honeypi_out/ holds both the
                            merged log and raw/, which would double-count)

Lines in the legacy merged.log.gz format (``<ISO_UTC>\\t<raw line>``) have
the prefix stripped, so callers always see the raw syslog line.

Folder inputs are merged into PacketTime order.  Each file must already be
time-sorted (as honeypi_out/raw/*.log and merged logs are); files are
ordered by their first PacketTime and opened only once the merge reaches
that time, so non-overlapping files stream one at a time and overlapping
ones interleave correctly.  Files that hold no PacketTime line in their
first few MB (binary indexes, unrelated logs) are skipped with a note.
Duplicates across files are not removed.
"""
from __future__ import annotations

import gzip
import heapq
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterator

GZIP_MAGIC = b"\x1f\x8b"
PEEK_BYTES = 4 << 20     # how far to look for the first PacketTime in a file

_PACKETTIME_RE = re.compile(rb"PacketTime:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)")


def is_gzip(path: Path) -> bool:
    with open(path, "rb") as f:
        return f.read(2) == GZIP_MAGIC


def describe(path: Path) -> str:
    """One-line summary of an input for the tools' [info] banner."""
    path = Path(path).expanduser()
    if path.is_dir():
        files = _candidates(path)
        size = sum(p.stat().st_size for p in files)
        return f"{path}  (folder, {len(files)} files, {size/1e9:.2f} GB)"
    kind = "gzip" if is_gzip(path) else "text"
    return f"{path}  ({kind}, {path.stat().st_size/1e9:.2f} GB)"


def iter_lines(path: Path, max_lines: int = 0) -> Iterator[bytes]:
    path = Path(path).expanduser()
    if not path.exists():
        raise FileNotFoundError(path)
    src = _iter_folder(path) if path.is_dir() else _iter_file(path)
    if not max_lines:
        yield from src
        return
    for n, line in enumerate(src, 1):
        yield line
        if n >= max_lines:
            break


# ----------------------------------------------------------------------
# Single files
# ----------------------------------------------------------------------

def _strip(raw: bytes) -> bytes:
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    # Merged-log lines are "<ISO>\t<rest>"; we only need the rest.
    # The ISO prefix starts with a digit; raw syslog starts with "Mon".
    if raw[:1].isdigit():
        tab = raw.find(b"\t", 0, 40)
        if tab != -1:
            return raw[tab + 1:]
    return raw


def _iter_file(path: Path) -> Iterator[bytes]:
    if not is_gzip(path):
        with open(path, "rb", buffering=1 << 22) as f:
            for raw in f:
                yield _strip(raw)
        return
    p = subprocess.Popen(["zcat", str(path)], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, bufsize=1 << 22)
    try:
        for raw in p.stdout:
            yield _strip(raw)
    finally:
        try:
            p.stdout.close()
        except Exception:
            pass
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()


# ----------------------------------------------------------------------
# Folders
# ----------------------------------------------------------------------

def _candidates(folder: Path) -> list[Path]:
    return sorted(p for p in folder.iterdir()
                  if p.is_file() and not p.name.startswith("."))


def _first_packettime(path: Path) -> bytes | None:
    """PacketTime of the first sensor line, or None for non-sensor files."""
    opener = gzip.open if is_gzip(path) else open
    try:
        with opener(path, "rb") as f:
            head = f.read(PEEK_BYTES)
    except (OSError, EOFError):
        return None
    if b"\0" in head[:4096]:
        return None             # binary (e.g. index/*.keys)
    m = _PACKETTIME_RE.search(head)
    return m.group(1) if m else None


def _keyed(path: Path) -> Iterator[tuple[bytes, bytes]]:
    """(PacketTime, line) pairs; lines without one inherit the last key."""
    key = b""
    for line in _iter_file(path):
        m = _PACKETTIME_RE.search(line)
        if m:
            key = m.group(1)
        yield key, line


def _iter_folder(folder: Path) -> Iterator[bytes]:
    pending: list[tuple[bytes, Path]] = []
    for p in _candidates(folder):
        t0 = _first_packettime(p)
        if t0 is None:
            print(f"[sensorlog] skip {p.name}: no sensor PacketTime lines",
                  file=sys.stderr)
            continue
        pending.append((t0, p))
    pending.sort()
    if not pending:
        raise ValueError(f"no sensor log files in {folder}")
    print(f"[sensorlog] {folder}: merging {len(pending)} files by PacketTime",
          file=sys.stderr)

    # Heap of (key, seq, line, iterator).  A file is opened only when the
    # merge front reaches its first PacketTime, so at most the overlapping
    # files are open at once.
    heap: list[tuple[bytes, int, bytes, Iterator[tuple[bytes, bytes]]]] = []
    seq = 0
    i = 0

    def _push(it: Iterator[tuple[bytes, bytes]]) -> None:
        nonlocal seq
        nxt = next(it, None)
        if nxt is not None:
            heapq.heappush(heap, (nxt[0], seq, nxt[1], it))
            seq += 1

    while heap or i < len(pending):
        while i < len(pending) and (not heap or pending[i][0] <= heap[0][0]):
            _push(_keyed(pending[i][1]))
            i += 1
        _, _, line, it = heapq.heappop(heap)
        yield line
        _push(it)


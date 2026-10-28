"""
Build sg.akd._akd, the Python 3.14 binding of BrainChip libakida.

    python src/sg/akd/build.py [--force]

1. Download the pinned akida wheel from PyPI into .tmp/akida_sdk/ and check
   its sha256.  The wheel is only a carrier: its CPython 3.12 module is not
   used.
2. Copy libakida.so.2 and its bundled libgomp to src/sg/akd/lib/ (same
   relative layout as in the wheel, so libakida's RPATH
   $ORIGIN/../akida.libs still resolves).
3. Compile _akd.cpp with pybind11 against the wheel's public headers, for
   the running interpreter.

The outputs (*.so, lib/) are build products; .gitignore already excludes
them.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import sysconfig
import urllib.request
import zipfile
from pathlib import Path

AKIDA_VERSION = "2.19.3"
WHEEL = f"akida-{AKIDA_VERSION}-cp312-cp312-manylinux_2_28_x86_64.whl"
WHEEL_URL = ("https://files.pythonhosted.org/packages/20/cd/"
             "a0bc639bad9aa8737a470e844f5e562ec5fe01b5f4401a113c579eb0b229/"
             + WHEEL)
WHEEL_SHA256 = "d74ab950535b3ee107d804ffddd6a80e3b104009ff6ce8ef659c38c63e885a55"

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SDK = ROOT / ".tmp" / "akida_sdk" / AKIDA_VERSION
LIB = HERE / "lib"


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch_sdk(force: bool) -> Path:
    whl = SDK / WHEEL
    if force or not whl.exists():
        SDK.mkdir(parents=True, exist_ok=True)
        print(f"[akd] download {WHEEL}")
        urllib.request.urlretrieve(WHEEL_URL, whl)
    got = _sha256(whl)
    if got != WHEEL_SHA256:
        raise SystemExit(f"[akd] sha256 mismatch for {whl}: {got}")
    src = SDK / "wheel"
    if force or not (src / "akida" / "libakida.so.2").exists():
        shutil.rmtree(src, ignore_errors=True)
        with zipfile.ZipFile(whl) as z:
            z.extractall(src)
    return src


def install_libs(src: Path) -> None:
    (LIB / "akida").mkdir(parents=True, exist_ok=True)
    (LIB / "akida.libs").mkdir(parents=True, exist_ok=True)
    shutil.copy2(src / "akida" / "libakida.so.2", LIB / "akida")
    for f in (src / "akida.libs").glob("libgomp*.so*"):
        shutil.copy2(f, LIB / "akida.libs")


def compile_module(src: Path) -> Path:
    import pybind11

    out = HERE / ("_akd" + sysconfig.get_config_var("EXT_SUFFIX"))
    cmd = [
        "g++", "-O2", "-std=c++20", "-shared", "-fPIC", "-fvisibility=hidden",
        "-Wall", "-Wno-unused-function",
        f"-I{pybind11.get_include()}",
        f"-I{sysconfig.get_path('include')}",
        f"-I{src / 'akida' / 'api'}",
        f"-I{src / 'akida' / 'engine' / 'api'}",
        str(HERE / "_akd.cpp"),
        f"-L{LIB / 'akida'}", "-l:libakida.so.2",
        "-Wl,-rpath,$ORIGIN/lib/akida",
        "-o", str(out),
    ]
    print("[akd] " + " ".join(cmd))
    subprocess.run(cmd, check=True)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--force", action="store_true",
                    help="download and extract the wheel again")
    args = ap.parse_args()
    src = fetch_sdk(args.force)
    install_libs(src)
    out = compile_module(src)
    print(f"[akd] built {out.relative_to(ROOT)} for Python "
          f"{sys.version.split()[0]}")


if __name__ == "__main__":
    main()

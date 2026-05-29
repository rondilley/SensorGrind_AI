#!/usr/bin/env python3
"""
sgquery — run all SensorGrind analyzer modules in dependency order.

Usage:
    python sgquery.py                     # run all analyzers
    python sgquery.py benignfilter        # run just one
    python sgquery.py --list              # show available analyzers
    python sgquery.py --since 2024-01-01  # time window for all
"""
from __future__ import annotations

import argparse
import importlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sg import lib

# Analyzers in dependency order (later ones may read earlier outputs).
ANALYZER_ORDER = [
    "benignfilter",
    "ja4plus",
    "fingerprint",
    "portscans",
    "droppers",
    "rdpbrute",
    "tlsintel",
    "probesigs",
    "scannerintel",
    "campaign",
    "botnetcls",
    "timing",
    "workhours",
    "emergence",
    "ecodanom",
    "trafficprint",
    "cveseries",      # depends on probesigs
    "clusterxref",    # depends on most others
    "attackmap",      # depends on probesigs, droppers, botnetcls, portscans, rdpbrute
]


def run_analyzer(name: str, args: argparse.Namespace) -> bool:
    try:
        mod = importlib.import_module(name)
        t0 = time.time()
        report = mod.run(args)
        paths = report.write()
        elapsed = time.time() - t0
        print(f"[sgquery] {name} done in {elapsed:.1f}s -> {paths['parquet']}",
              file=sys.stderr)
        return True
    except Exception as e:
        print(f"[sgquery] {name} FAILED: {e}", file=sys.stderr)
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("analyzers", nargs="*", help="Specific analyzers to run (default: all)")
    ap.add_argument("--list", action="store_true", help="List available analyzers")
    lib.add_window_args(ap)
    args = ap.parse_args()

    if args.list:
        for i, name in enumerate(ANALYZER_ORDER, 1):
            print(f"  {i:2d}. {name}")
        return 0

    to_run = args.analyzers if args.analyzers else ANALYZER_ORDER

    invalid = [a for a in to_run if a not in ANALYZER_ORDER]
    if invalid:
        print(f"Unknown analyzers: {', '.join(invalid)}", file=sys.stderr)
        print(f"Available: {', '.join(ANALYZER_ORDER)}", file=sys.stderr)
        return 2

    t0 = time.time()
    passed = 0
    failed = 0
    for name in to_run:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"[sgquery] running {name}...", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        if run_analyzer(name, args):
            passed += 1
        else:
            failed += 1

    elapsed = time.time() - t0
    print(f"\n[sgquery] finished: {passed} passed, {failed} failed, {elapsed:.0f}s total",
          file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

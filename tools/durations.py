#!/usr/bin/env python3
"""Per-test-file durations: record them from a run, balance shards by them, and cap one file's share.

    python tools/durations.py shards FILE   # a JSON list of shard numbers, sized from FILE
    python tools/durations.py merge OUT IN...   # one file from the shards' files
    python tools/durations.py check FILE    # fail when one file is too slow to share a shard

Wall-clock seconds per file are the sum of its tests' durations divided by the runner's workers.
A missing or unreadable FILE is "no data": a default shard count, and the hash split in shard_tests.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

#: Cores on a hosted runner, which pytest -n auto spreads one shard's tests across.
WORKERS = 4
#: Wall seconds one shard should take; a catalog twice as slow gets twice the shards.
TARGET = 360.0
#: No single file may take longer than this, or no split can balance it.
CAP = 300.0
DEFAULT_SHARDS = 4
MAX_SHARDS = 16


def load(path: str | Path) -> dict[str, float]:
    """File -> seconds, or {} when the file is missing, unreadable or not that shape."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    ok = isinstance(data, dict) and all(isinstance(k, str) and isinstance(v, int | float) for k, v in data.items())
    return {k: float(v) for k, v in data.items()} if ok else {}


def merge(parts: list[dict[str, float]]) -> dict[str, float]:
    """The union of the shards' files; a file is run by one shard, so the totals add."""
    out: dict[str, float] = defaultdict(float)
    for part in parts:
        for name, seconds in part.items():
            out[name] += seconds
    return dict(sorted(out.items()))


def wall(seconds: float, workers: int = WORKERS) -> float:
    return seconds / workers


def shard_count(durations: dict[str, float], target: float = TARGET, workers: int = WORKERS) -> int:
    """How many shards keep each under `target` wall seconds, or the default with no data."""
    if not durations:
        return DEFAULT_SHARDS
    return min(MAX_SHARDS, max(1, math.ceil(wall(sum(durations.values()), workers) / target)))


def balance(files: list[str], durations: dict[str, float], total: int) -> dict[str, int]:
    """File -> shard number (1..total), longest first into the lightest shard; unknown files cost the mean."""
    known = [durations[f] for f in files if f in durations]
    mean = sum(known) / len(known) if known else 1.0
    cost = {f: durations.get(f, mean) for f in files}
    load_of = [0.0] * total
    out: dict[str, int] = {}
    for name in sorted(files, key=lambda f: (-cost[f], f)):
        lightest = min(range(total), key=lambda i: (load_of[i], i))
        load_of[lightest] += cost[name]
        out[name] = lightest + 1
    return out


def too_slow(durations: dict[str, float], cap: float = CAP, workers: int = WORKERS) -> dict[str, float]:
    """The files whose wall seconds exceed the cap, slowest first."""
    over = {f: wall(s, workers) for f, s in durations.items() if wall(s, workers) > cap}
    return dict(sorted(over.items(), key=lambda kv: -kv[1]))


class Recorder:
    """A pytest plugin: sum every test phase's seconds by file and write them when the session ends."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.seconds: dict[str, float] = defaultdict(float)

    def pytest_runtest_logreport(self, report) -> None:
        self.seconds[report.nodeid.partition("::")[0]] += report.duration

    def pytest_sessionfinish(self) -> None:
        self.path.write_text(json.dumps(merge([self.seconds]), indent=1) + "\n", encoding="utf-8")


def add_option(parser) -> None:
    parser.addoption("--durations-out", default=None, metavar="FILE", help="write seconds per test file to FILE")


def configure(config) -> None:
    """Record into --durations-out; an xdist worker leaves that to the controller, which sees every report."""
    if (path := config.getoption("--durations-out")) and not hasattr(config, "workerinput"):
        config.pluginmanager.register(Recorder(path))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    shards = sub.add_parser("shards")
    shards.add_argument("file")
    shards.add_argument("--target", type=float, default=TARGET)
    shards.add_argument("--workers", type=int, default=WORKERS)
    joined = sub.add_parser("merge")
    joined.add_argument("out")
    joined.add_argument("inputs", nargs="+")
    check = sub.add_parser("check")
    check.add_argument("file")
    check.add_argument("--cap", type=float, default=CAP)
    check.add_argument("--workers", type=int, default=WORKERS)
    args = parser.parse_args(argv)
    if args.command == "shards":
        count = shard_count(load(args.file), args.target, args.workers)
        print(json.dumps(list(range(1, count + 1))))
        return 0
    if args.command == "merge":
        Path(args.out).write_text(json.dumps(merge([load(i) for i in args.inputs]), indent=1) + "\n", encoding="utf-8")
        return 0
    slow = too_slow(load(args.file), args.cap, args.workers)
    for name, seconds in slow.items():
        print(
            f"{name}: about {seconds:.0f}s of wall time, over the {args.cap:.0f}s cap; split it by activity",
            file=sys.stderr,
        )
    return 1 if slow else 0


if __name__ == "__main__":
    raise SystemExit(main())

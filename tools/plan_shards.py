#!/usr/bin/env python3
"""Plan a full run's shards from the per-file times the last run on main recorded.

    python tools/plan_shards.py junit OUT.json JUNIT.xml...   # per file: summed seconds, longest test, from junit files
    python tools/plan_shards.py plan TIMES.json               # JSON: shard count, each file's shard, files to split
    python tools/plan_shards.py check TIMES.json [--warn]     # a single test over the cap fails; near it is a warning

A file's seconds are its tests' summed times; a shard runs them on WORKERS cores, so its wall time is that over
WORKERS, but never less than its longest test, which one core runs alone. Whole files are packed longest first into
the lightest shard. A file longer than a shard is not packed: its tests go to the shard their node id hashes to
(shard_tests.slice_of), so the slices still partition the suite. With no times the plan is the plain four-way hash
split. A missing, unreadable or old-format (file to seconds) TIMES file is no times. The cap is on one test, the one
unit that cannot be split: a file of many short tests is balanced across shards and never fails it.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import re
import sys
from pathlib import Path
from typing import NamedTuple

#: Cores on a hosted runner, which pytest -n auto spreads a shard's tests across.
WORKERS = 4
#: Wall seconds of tests one shard should take; with setup, a shard then runs about six minutes.
TARGET = 270.0
MIN_SHARDS, MAX_SHARDS = 4, 16
#: No single test may take longer than this on a full run: it fails the durations job on main.
CAP = 300.0
#: A test this close to the cap draws a warning on a pull request.
WARN_AT = 0.8
TESTCASE = re.compile(r"<testcase\b([^>]*)>")
ATTRIBUTE = re.compile(r'(\w+)="([^"]*)"')


class Times(NamedTuple):
    """One test file's recorded time: summed seconds over its tests, and its longest single test."""

    seconds: float
    longest: float
    test: str


def number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def load(path: str | Path) -> dict[str, Times]:
    """File -> Times, or {} when the file is missing, unreadable, or not that shape (an old file -> seconds is not)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, Times] = {}
    for name, found in data.items():
        if not (isinstance(found, dict) and number(found.get("seconds")) and number(found.get("longest"))):
            return {}
        if not isinstance(found.get("test"), str):
            return {}
        out[name] = Times(float(found["seconds"]), float(found["longest"]), found["test"])
    return out


def test_file(classname: str, root: Path) -> str | None:
    """The test file a junit classname names: its longest dotted prefix that is a .py file under root."""
    parts = classname.split(".")
    for end in range(len(parts), 0, -1):
        rel = "/".join(parts[:end]) + ".py"
        if (root / rel).is_file():
            return rel
    return None


def times_from_junit(paths: list[str], root: Path) -> dict[str, Times]:
    """Per test file, summed over every junit file given: its seconds, and its longest test with that test's name."""
    out: dict[str, Times] = {}
    for path in paths:
        for match in TESTCASE.finditer(Path(path).read_text(encoding="utf-8")):
            attrs = dict(ATTRIBUTE.findall(match.group(1)))
            name = test_file(attrs.get("classname", ""), root)
            if name:
                seconds = float(attrs.get("time", 0))
                before = out.get(name, Times(0.0, 0.0, ""))
                test = html.unescape(attrs.get("name", ""))
                longest = (seconds, test) if seconds > before.longest else (before.longest, before.test)
                out[name] = Times(before.seconds + seconds, *longest)
    return dict(sorted(out.items()))


def wall(times: Times, workers: int = WORKERS) -> float:
    """Wall seconds of a file on a shard: its tests spread over the workers, but one test runs on one core."""
    return max(times.seconds / workers, times.longest)


def plan(times: dict[str, Times], target: float = TARGET, workers: int = WORKERS) -> dict:
    """{"shards", "assignment": file -> shard 1..shards, "split": [files], "source"}; the hash split with no times."""
    if not times:
        return {"shards": MIN_SHARDS, "assignment": {}, "split": [], "source": "none"}
    cost = {name: wall(found, workers) for name, found in times.items()}
    shards = min(MAX_SHARDS, max(MIN_SHARDS, math.ceil(sum(cost.values()) / target)))
    split = sorted(name for name, seconds in cost.items() if seconds > target)
    loads = [sum(cost[name] for name in split) / shards] * shards
    assignment: dict[str, int] = {}
    for name in sorted((n for n in cost if n not in split), key=lambda n: (-cost[n], n)):
        lightest = min(range(shards), key=lambda i: (loads[i], i))
        loads[lightest] += cost[name]
        assignment[name] = lightest + 1
    return {"shards": shards, "assignment": assignment, "split": split, "source": "durations"}


def load_plan(path: str | Path) -> dict:
    """A plan file, checked: anything but a well-formed plan is an error, never a silent change of split."""
    try:
        found = json.loads(Path(path).read_text(encoding="utf-8"))
        shards, assignment = found["shards"], found["assignment"]
        ok = isinstance(shards, int) and shards >= 1 and isinstance(assignment, dict)
        ok = ok and all(isinstance(k, str) and isinstance(v, int) and 1 <= v <= shards for k, v in assignment.items())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        message = f"{path} is not a shard plan: {exc}"
        raise ValueError(message) from exc
    if not ok:
        message = f"{path} is not a shard plan"
        raise ValueError(message)
    return found


def over(times: dict[str, Times], limit: float) -> dict[str, tuple[str, float]]:
    """File -> (its longest test, that test's seconds) for the files whose longest test exceeds `limit`, slowest first."""
    slow = {name: (found.test, found.longest) for name, found in times.items() if found.longest > limit}
    return dict(sorted(slow.items(), key=lambda kv: -kv[1][1]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    junit = sub.add_parser("junit")
    junit.add_argument("out")
    junit.add_argument("inputs", nargs="+")
    sub.add_parser("plan").add_argument("times")
    check = sub.add_parser("check")
    check.add_argument("times")
    check.add_argument("--warn", action="store_true", help="only warn; never fail")
    args = parser.parse_args(argv)
    if args.command == "junit":
        found = times_from_junit(args.inputs, Path.cwd())
        text = json.dumps({name: v._asdict() for name, v in found.items()}, indent=1)
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        return 0
    times = load(args.times)
    if args.command == "plan":
        chosen = plan(times)
        if chosen["source"] == "none":
            print("no recorded times: the four-way hash split", file=sys.stderr)
        print(json.dumps(chosen))
        return 0
    for name, (test, seconds) in over(times, CAP).items():
        print(f"::error::{name}::{test} takes {seconds:.0f}s, over the {CAP:.0f}s cap; split the test by activity")
    for name, (test, seconds) in over(times, CAP * WARN_AT).items():
        if seconds <= CAP:
            print(f"::warning::{name}::{test} takes {seconds:.0f}s, over {WARN_AT:.0%} of the {CAP:.0f}s cap")
    return 1 if over(times, CAP) and not args.warn else 0


if __name__ == "__main__":
    raise SystemExit(main())

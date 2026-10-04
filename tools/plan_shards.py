#!/usr/bin/env python3
"""Plan a full run's shards from the per-file times the last run on main recorded.

    python tools/plan_shards.py junit OUT.json JUNIT.xml...   # seconds per test file, from pytest --junitxml files
    python tools/plan_shards.py plan TIMES.json               # JSON: shard count, each file's shard, files to split
    python tools/plan_shards.py check TIMES.json [--warn]     # a file over the cap fails; near it is a warning

A file's seconds are its tests' summed times; a shard runs them on WORKERS cores, so wall time is that over WORKERS.
Whole files are packed longest first into the lightest shard. A file longer than a shard is not packed: its tests
go to the shard their node id hashes to (shard_tests.slice_of), so the slices still partition the suite. With no
times the plan is the plain four-way hash split. A missing or unreadable TIMES file is no times. `check` skips the one file in EXEMPT, and says so every run.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

#: Cores on a hosted runner, which pytest -n auto spreads a shard's tests across.
WORKERS = 4
#: Wall seconds of tests one shard should take; with setup, a shard then runs about six minutes.
TARGET = 270.0
MIN_SHARDS, MAX_SHARDS = 4, 16
#: No file may take longer than this on a full run: it fails the durations job on main.
CAP = 300.0
#: A file this close to the cap draws a warning on a pull request.
WARN_AT = 0.8
#: The one file allowed past the cap, with why. Temporary: parametrizing it per policy removes the entry.
EXEMPT = {
    "tests/policies/test_every_policy.py": "walks every policy in one file, with a 372 s serial case; to be parametrized per policy",
}
TESTCASE = re.compile(r"<testcase\b([^>]*)>")
ATTRIBUTE = re.compile(r'(\w+)="([^"]*)"')


def load(path: str | Path) -> dict[str, float]:
    """File -> seconds, or {} when the file is missing, unreadable or not that shape."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    ok = isinstance(data, dict) and all(isinstance(k, str) and isinstance(v, int | float) for k, v in data.items())
    return {k: float(v) for k, v in data.items()} if ok else {}


def test_file(classname: str, root: Path) -> str | None:
    """The test file a junit classname names: its longest dotted prefix that is a .py file under root."""
    parts = classname.split(".")
    for end in range(len(parts), 0, -1):
        rel = "/".join(parts[:end]) + ".py"
        if (root / rel).is_file():
            return rel
    return None


def times_from_junit(paths: list[str], root: Path) -> dict[str, float]:
    """Seconds per test file, summed over every junit file given."""
    out: dict[str, float] = {}
    for path in paths:
        for match in TESTCASE.finditer(Path(path).read_text(encoding="utf-8")):
            attrs = dict(ATTRIBUTE.findall(match.group(1)))
            name = test_file(attrs.get("classname", ""), root)
            if name:
                out[name] = out.get(name, 0.0) + float(attrs.get("time", 0))
    return dict(sorted(out.items()))


def wall(seconds: float, workers: int = WORKERS) -> float:
    return seconds / workers


def plan(times: dict[str, float], target: float = TARGET, workers: int = WORKERS) -> dict:
    """{"shards", "assignment": file -> shard 1..shards, "split": [files], "source"}; the hash split with no times."""
    if not times:
        return {"shards": MIN_SHARDS, "assignment": {}, "split": [], "source": "none"}
    cost = {name: wall(seconds, workers) for name, seconds in times.items()}
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


def over(times: dict[str, float], limit: float, workers: int = WORKERS) -> dict[str, float]:
    """The files whose wall seconds exceed `limit`, slowest first."""
    slow = {name: wall(seconds, workers) for name, seconds in times.items() if wall(seconds, workers) > limit}
    return dict(sorted(slow.items(), key=lambda kv: -kv[1]))


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
        Path(args.out).write_text(json.dumps(found, indent=1) + "\n", encoding="utf-8")
        return 0
    times = load(args.times)
    if args.command == "plan":
        chosen = plan(times)
        if chosen["source"] == "none":
            print("no recorded times: the four-way hash split", file=sys.stderr)
        print(json.dumps(chosen))
        return 0
    counted = {name: seconds for name, seconds in times.items() if name not in EXEMPT}
    for name, reason in EXEMPT.items():
        print(f"::warning::{name} is exempt from the {CAP:.0f}s cap, temporarily: {reason}")
    for name, seconds in over(counted, CAP).items():
        print(f"::error::{name} takes about {seconds:.0f}s of wall time, over the {CAP:.0f}s cap; split it by activity")
    for name, seconds in over(counted, CAP * WARN_AT).items():
        if seconds <= CAP:
            print(
                f"::warning::{name} takes about {seconds:.0f}s of wall time, over {WARN_AT:.0%} of the {CAP:.0f}s cap"
            )
    return 1 if over(counted, CAP) and not args.warn else 0


if __name__ == "__main__":
    raise SystemExit(main())

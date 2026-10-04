#!/usr/bin/env python3
"""Plan a full run's shards from the per-file times the last run on main recorded.

    python tools/plan_shards.py junit OUT.json JUNIT.xml...   # per file: summed seconds, longest test, from junit files
    python tools/plan_shards.py plan TIMES.json               # JSON: shard count, each file's shard, files to split
    python tools/plan_shards.py check TIMES.json [--warn]     # a single test over the cap fails; near it is a warning
    python tools/plan_shards.py report PLAN.json JUNIT.xml... # markdown: slowest tests and files, shards planned vs actual

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
import statistics
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
SUITE = re.compile(r"<testsuite\b([^>]*)>")
SHARD_FILE = re.compile(r"junit-(\d+)\.xml$")
#: Rows of the slow-test report.
SLOWEST_TESTS, SLOWEST_FILES = 20, 10


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
    """{"shards", "assignment": file -> shard, "split": [files], "source", "planned": seconds per shard}; no times: hash split."""
    if not times:
        return {"shards": MIN_SHARDS, "assignment": {}, "split": [], "source": "none", "planned": []}
    cost = {name: wall(found, workers) for name, found in times.items()}
    shards = min(MAX_SHARDS, max(MIN_SHARDS, math.ceil(sum(cost.values()) / target)))
    split = sorted(name for name, seconds in cost.items() if seconds > target)
    loads = [sum(cost[name] for name in split) / shards] * shards
    assignment: dict[str, int] = {}
    for name in sorted((n for n in cost if n not in split), key=lambda n: (-cost[n], n)):
        lightest = min(range(shards), key=lambda i: (loads[i], i))
        loads[lightest] += cost[name]
        assignment[name] = lightest + 1
    planned = [round(load, 1) for load in loads]
    return {"shards": shards, "assignment": assignment, "split": split, "source": "durations", "planned": planned}


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


def cell(text: str) -> str:
    """Text safe inside a markdown table cell."""
    return text.replace("|", "\\|").replace("`", "'")


def report(found: dict, paths: list[str], root: Path) -> str:
    """Markdown for a step summary: the slowest tests and files of a run, and each shard planned versus actual."""
    cases: list[tuple[float, str]] = []
    actual: dict[int, float] = {}
    for position, path in enumerate(paths, 1):
        text = Path(path).read_text(encoding="utf-8")
        named = SHARD_FILE.search(path)
        suite = SUITE.search(text)
        suite_attrs = dict(ATTRIBUTE.findall(suite.group(1))) if suite else {}
        actual[int(named.group(1)) if named else position] = float(suite_attrs.get("time", 0))
        for match in TESTCASE.finditer(text):
            attrs = dict(ATTRIBUTE.findall(match.group(1)))
            label = html.unescape(f"{attrs.get('classname', '')}::{attrs.get('name', '')}")
            cases.append((float(attrs.get("time", 0)), label))
    median = statistics.median(actual.values())
    lines = ["## Slowest tests", "", "| seconds | test |", "|---:|---|"]
    lines += [f"| {seconds:.1f} | `{cell(label)}` |" for seconds, label in sorted(cases, reverse=True)[:SLOWEST_TESTS]]
    lines += ["", "## Slowest files", "", "| summed seconds | longest test seconds | file |", "|---:|---:|---|"]
    by_file = sorted(times_from_junit(paths, root).items(), key=lambda kv: (-kv[1].seconds, kv[0]))
    lines += [f"| {v.seconds:.1f} | {v.longest:.1f} | `{cell(name)}` |" for name, v in by_file[:SLOWEST_FILES]]
    lines += [
        "",
        "## Shards, planned versus actual",
        "",
        "| shard | planned seconds | actual seconds | actual / median |",
        "|---:|---:|---:|---:|",
    ]
    planned = found.get("planned", [])
    for shard in sorted(actual):
        plan_cell = f"{planned[shard - 1]:.0f}" if shard <= len(planned) else "-"
        ratio = actual[shard] / median if median else 0.0
        lines.append(f"| {shard} | {plan_cell} | {actual[shard]:.0f} | {ratio:.2f} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    junit = sub.add_parser("junit")
    junit.add_argument("out")
    junit.add_argument("inputs", nargs="+")
    sub.add_parser("plan").add_argument("times")
    summary = sub.add_parser("report")
    summary.add_argument("plan")
    summary.add_argument("inputs", nargs="+")
    check = sub.add_parser("check")
    check.add_argument("times")
    check.add_argument("--warn", action="store_true", help="only warn; never fail")
    args = parser.parse_args(argv)
    if args.command == "junit":
        found = times_from_junit(args.inputs, Path.cwd())
        text = json.dumps({name: v._asdict() for name, v in found.items()}, indent=1)
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        return 0
    if args.command == "report":
        print(report(load_plan(args.plan), args.inputs, Path.cwd()), end="")
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

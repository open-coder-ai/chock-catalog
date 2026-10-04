"""Run one deterministic slice of the suite: `pytest --shard 2/4` runs the second of four.

A test belongs to the slice its node id hashes to, so the slices partition whatever is collected --
none twice, none dropped -- with no list to keep. crc32 rather than hash(): every xdist worker
collects on its own and must keep the same tests, and hash() differs per process.

With `--shard-plan FILE` (tools/plan_shards.py) a test file named in the plan goes whole to the slice the plan
gives it, packed by the time it took last run so the slices finish together; every other test, including those of a
file too long to pack, keeps the hash. The plan must be for the same number of slices as the spec, or it is an error.
"""

from __future__ import annotations

import zlib

import plan_shards
import pytest


def parse(spec: str) -> tuple[int, int]:
    """'2/4' -> (2, 4). Anything else is a usage error, never an empty or whole-suite run."""
    index, _, total = spec.partition("/")
    if not (index.isdecimal() and total.isdecimal() and 1 <= int(index) <= int(total)):
        message = f"--shard wants N/M with 1 <= N <= M, not {spec!r}"
        raise pytest.UsageError(message)
    return int(index), int(total)


def slice_of(nodeid: str, total: int) -> int:
    return zlib.crc32(nodeid.encode()) % total + 1


def add_option(parser: pytest.Parser) -> None:
    parser.addoption("--shard", default=None, metavar="N/M", help="run only slice N of M of the collected tests")
    parser.addoption("--shard-plan", default=None, metavar="FILE", help="pack whole test files by the plan's times")


def file_of(item: pytest.Item) -> str:
    return item.nodeid.partition("::")[0]


def slicer(config: pytest.Config, total: int):
    """item -> slice number: its file's slice in the plan, else the hash of its node id."""
    if not (path := config.getoption("--shard-plan")):
        return lambda item: slice_of(item.nodeid, total)
    try:
        plan = plan_shards.load_plan(path)
    except ValueError as exc:
        raise pytest.UsageError(str(exc)) from exc
    if plan["shards"] != total:
        message = f"{path} is a plan for {plan['shards']} shards, not {total}"
        raise pytest.UsageError(message)
    return lambda item: plan["assignment"].get(file_of(item)) or slice_of(item.nodeid, total)


def apply(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Keep this slice's items in place and report the rest as deselected."""
    spec = config.getoption("--shard")
    if spec is None:
        return
    index, total = parse(spec)
    which = slicer(config, total)
    kept = [item for item in items if which(item) == index]
    dropped = [item for item in items if which(item) != index]
    if dropped:
        config.hook.pytest_deselected(items=dropped)
    items[:] = kept

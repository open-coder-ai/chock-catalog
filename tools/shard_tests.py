"""Run one deterministic slice of the suite: `pytest --shard 2/4` runs the second of four.

A test belongs to the slice its node id hashes to, so the slices partition whatever is collected --
none twice, none dropped -- with no list to keep. crc32 rather than hash(): every xdist worker
collects on its own and must keep the same tests, and hash() differs per process.
"""

from __future__ import annotations

import zlib

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


def apply(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Keep this slice's items in place and report the rest as deselected."""
    spec = config.getoption("--shard")
    if spec is None:
        return
    index, total = parse(spec)
    kept = [item for item in items if slice_of(item.nodeid, total) == index]
    dropped = [item for item in items if slice_of(item.nodeid, total) != index]
    if dropped:
        config.hook.pytest_deselected(items=dropped)
    items[:] = kept

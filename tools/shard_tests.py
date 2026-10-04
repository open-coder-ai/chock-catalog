"""Run one deterministic slice of the suite: `pytest --shard 2/4` runs the second of four.

A test belongs to the slice its node id hashes to, so the slices partition whatever is collected --
none twice, none dropped -- with no list to keep. crc32 rather than hash(): every xdist worker
collects on its own and must keep the same tests, and hash() differs per process.

With `--shard-durations FILE` (tools/durations.py) a whole test file goes to one slice instead, packed by
the time the file took last run, so the slices finish together. An unreadable FILE falls back to the hash.
"""

from __future__ import annotations

import zlib

import durations
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
    parser.addoption(
        "--shard-durations", default=None, metavar="FILE", help="balance the slices by recorded file times"
    )


def file_of(item: pytest.Item) -> str:
    return item.nodeid.partition("::")[0]


def slicer(config: pytest.Config, items: list[pytest.Item], total: int):
    """item -> slice number: the packed slice of its file when times are recorded, else the hash of its id."""
    recorded = durations.load(path) if (path := config.getoption("--shard-durations")) else {}
    if not recorded:
        return lambda item: slice_of(item.nodeid, total)
    packed = durations.balance(sorted({file_of(item) for item in items}), recorded, total)
    return lambda item: packed[file_of(item)]


def apply(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Keep this slice's items in place and report the rest as deselected."""
    spec = config.getoption("--shard")
    if spec is None:
        return
    index, total = parse(spec)
    which = slicer(config, items, total)
    kept = [item for item in items if which(item) == index]
    dropped = [item for item in items if which(item) != index]
    if dropped:
        config.hook.pytest_deselected(items=dropped)
    items[:] = kept

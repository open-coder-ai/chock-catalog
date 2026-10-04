"""Run one policy's share of a suite: `pytest --policy ID` drops the rows that name another policy and none of ID.

A row names a policy when a whole word of its parameters is that policy's id (underscores read as hyphens).
A test with no such row, or a row naming no policy, always runs: only a row clearly about another policy goes.
"""

from __future__ import annotations

import re

import pytest
from trees import policy_dirs

WORD = re.compile(r"[\w-]+")


def named(nodeid: str, ids: set[str]) -> set[str]:
    """The policy ids that are whole words in the parameters of a row's node id."""
    _, bracket, params = nodeid.partition("[")
    words = WORD.findall(params) if bracket else []
    return {w for word in words for w in (word, word.replace("_", "-")) if w in ids}


def add_option(parser: pytest.Parser) -> None:
    parser.addoption("--policy", action="append", default=None, metavar="ID", help="keep only rows about this policy")


def apply(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Keep the rows about no policy or about ID, and report the rest as deselected."""
    wanted = config.getoption("--policy")
    if not wanted:
        return
    ids = {p.name for p in policy_dirs()}
    if unknown := sorted(set(wanted) - ids):
        message = f"--policy names no policy: {', '.join(unknown)}"
        raise pytest.UsageError(message)
    keep = [i for i in items if not (found := named(i.nodeid, ids)) or found & set(wanted)]
    if len(keep) != len(items):
        config.hook.pytest_deselected(items=[i for i in items if i not in keep])
    items[:] = keep

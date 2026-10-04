"""`pytest --shard N/M [--shard-plan FILE]` and `--policy ID`: CI's slices of the suite (tools/shard_tests.py, tools/policy_rows.py).

Here, at the repo root, and not in tests/: while the command line is parsed an option is not yet known, so
its value (`--shard-plan shard-plan.json`) reads as a path, and pytest then looks for conftests
beside that path instead of under tests/. The root one is found whichever way the options are spelled.
"""

from __future__ import annotations

import policy_rows
import pytest
import shard_tests


def pytest_addoption(parser: pytest.Parser) -> None:
    shard_tests.add_option(parser)
    policy_rows.add_option(parser)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    policy_rows.apply(config, items)
    shard_tests.apply(config, items)

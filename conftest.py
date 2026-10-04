"""`pytest --shard N/M`, `--policy ID` and `--durations-out FILE`: CI's slices of the suite and its timings.

Here, at the repo root, and not in tests/: while the command line is parsed an option is not yet known, so
its value (`--shard-durations test-durations.json`) reads as a path, and pytest then looks for conftests
beside that path instead of under tests/. The root one is found whichever way the options are spelled.
"""

from __future__ import annotations

import durations
import policy_rows
import pytest
import shard_tests


def pytest_addoption(parser: pytest.Parser) -> None:
    shard_tests.add_option(parser)
    policy_rows.add_option(parser)
    durations.add_option(parser)


def pytest_configure(config: pytest.Config) -> None:
    durations.configure(config)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    policy_rows.apply(config, items)
    shard_tests.apply(config, items)

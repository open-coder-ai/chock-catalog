"""`pytest --shard N/M`, `--policy ID` and `--durations-out FILE`: CI's slices of the suite and its timings."""

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

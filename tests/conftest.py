"""`pytest --shard N/M`: one slice of the suite, for CI's parallel jobs (tools/shard_tests.py)."""

from __future__ import annotations

import pytest
import shard_tests


def pytest_addoption(parser: pytest.Parser) -> None:
    shard_tests.add_option(parser)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    shard_tests.apply(config, items)

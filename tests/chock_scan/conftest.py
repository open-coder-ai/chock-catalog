"""The `yp` fixture: every yamlpath test runs against lib/ and every copy a policy ships."""

from __future__ import annotations

from types import ModuleType

import pytest
from chock_scan.yamlkit import IDS, SOURCES, load


@pytest.fixture(params=SOURCES, ids=IDS)
def yp(request: pytest.FixtureRequest) -> ModuleType:
    return load(request.param)

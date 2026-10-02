"""The `m` fixture: chock_scan's HCL modules, once from lib/ and once from each copy a policy ships."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from chock_scan.hclload import IDS, SOURCES, load


@pytest.fixture(params=SOURCES, ids=IDS)
def m(request: pytest.FixtureRequest) -> SimpleNamespace:
    return load(request.param)

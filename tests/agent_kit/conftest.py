"""The agent kit's tests spawn chock, git and hook processes that run no measured source."""

from __future__ import annotations

import pytest

#: How coverage's `patch = ["subprocess"]` reaches a child process: while one of these is set,
#: every Python child starts a tracer at import time. These tests start hundreds of children
#: (chock init/sync, git hooks) and none of them runs code under [tool.coverage.run] source, so the
#: tracer doubled this directory's time for nothing. Code these tests import in-process is still
#: measured; tests/java_security and tests/a11y keep subprocess measurement for the shipped gates.
_COVERAGE_CHILD_ENV = ("COVERAGE_PROCESS_CONFIG", "COVERAGE_PROCESS_START")


@pytest.fixture(autouse=True)
def _unmeasured_children(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _COVERAGE_CHILD_ENV:
        monkeypatch.delenv(name, raising=False)

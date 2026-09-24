"""Every statement of every shipped bash guard is run by at least one of its policy's eval cases.

A branch no case reaches is a branch nobody has seen decide: it may refuse what it should allow,
or never be reachable at all. The cases are the same ones test_every_policy replays; here they
are replayed once more under bash's trace (shellcov.py) and each guard must be fully covered.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from chock.eval.execute import run_case
from chock.eval.suites import Policy, load_cases
from chock.manifest import load_manifest
from policies.shellcov import statements, tracing, uncovered
from trees import ROOT, policy_dirs


def _guarded() -> list[tuple[Path, Path]]:
    rows = []
    for policy_dir in policy_dirs():
        loaded = load_manifest(policy_dir)
        guards = Policy(policy_dir.name, policy_dir, loaded[0]).guards if loaded else []
        rows += [(policy_dir, g) for g in guards if g.suffix == ".sh"]
    return rows


GUARDED = _guarded()


@pytest.fixture(scope="module")
def trace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    with tracing(tmp_path_factory.mktemp("shellcov")) as path:
        for policy_dir, guard in GUARDED:
            for case in load_cases(policy_dir, policy_dir.name):
                if case.execute and "command" in case.execute:
                    run_case(case, policy_dir, ROOT, [guard])
    return path


def test_every_bash_guard_is_measured() -> None:
    assert len(GUARDED) >= 9


@pytest.mark.parametrize(("policy_dir", "guard"), GUARDED, ids=[p.name for p, _ in GUARDED])
def test_every_statement_of_the_guard_is_run_by_a_case(policy_dir: Path, guard: Path, trace: Path) -> None:
    assert statements(guard.read_text(encoding="utf-8")), f"{guard.name} parsed to no statements"
    missing = [lines[0] for lines in uncovered(guard, trace)]
    assert missing == [], f"{policy_dir.name}: no eval case runs {guard.name} lines {missing}"

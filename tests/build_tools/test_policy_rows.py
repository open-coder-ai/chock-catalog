"""policy_rows.py: `--policy ID` keeps a row unless it is clearly about another policy."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import policy_rows
import pytest

ROOT = Path(__file__).resolve().parents[2]
IDS = {"scan-secrets", "scan-secrets-entropy", "git-safety"}


@pytest.mark.parametrize(
    ("nodeid", "found"),
    [
        ("t.py::test[scan-secrets]", {"scan-secrets"}),
        ("t.py::test[scan-secrets-entropy::case-1]", {"scan-secrets-entropy"}),
        ("t.py::test[scan_secrets_entropy]", {"scan-secrets-entropy"}),
        ("t.py::test[git-safety-scan-secrets]", set()),
        ("t.py::test[base/git-safety/x.yaml-scan-secrets]", {"git-safety"}),
        ("t.py::test[scan-secrets|git-safety]", {"scan-secrets", "git-safety"}),
        ("t.py::test[other]", set()),
        ("t.py::test_scan_secrets", set()),
        ("t.py::test", set()),
    ],
)
def test_a_row_names_the_policies_that_are_whole_words_of_its_parameters(nodeid: str, found: set[str]) -> None:
    assert policy_rows.named(nodeid, IDS) == found


def items(*nodeids: str) -> list[SimpleNamespace]:
    return [SimpleNamespace(nodeid=n) for n in nodeids]


def config(wanted: list[str] | None, dropped: list[list[object]]) -> SimpleNamespace:
    def pytest_deselected(items: list[object]) -> None:
        dropped.append(items)

    hook = SimpleNamespace(pytest_deselected=pytest_deselected)
    return SimpleNamespace(getoption=lambda _: wanted, hook=hook)


def test_apply_drops_only_rows_about_other_policies() -> None:
    rows = items(
        "t.py::t[scan-secrets]",
        "t.py::t[scan-secrets-entropy]",
        "t.py::t[git-safety]",
        "t.py::t[no-policy-here]",
        "t.py::plain",
    )
    dropped: list[list[object]] = []
    policy_rows.apply(config(["scan-secrets-entropy"], dropped), rows)
    assert [r.nodeid for r in rows] == ["t.py::t[scan-secrets-entropy]", "t.py::t[no-policy-here]", "t.py::plain"]
    assert [r.nodeid for r in dropped[0]] == ["t.py::t[scan-secrets]", "t.py::t[git-safety]"]


def test_more_than_one_policy_keeps_the_rows_of_each(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy_rows, "policy_dirs", lambda: [Path(i) for i in sorted(IDS)])
    rows = items("t.py::t[scan-secrets]", "t.py::t[git-safety]", "t.py::t[scan-secrets-entropy]")
    policy_rows.apply(config(["scan-secrets", "git-safety"], []), rows)
    assert [r.nodeid for r in rows] == ["t.py::t[scan-secrets]", "t.py::t[git-safety]"]


def test_no_policy_option_keeps_everything_and_deselects_nothing() -> None:
    rows = items("t.py::t[scan-secrets]", "t.py::t[git-safety]")
    dropped: list[list[object]] = []
    policy_rows.apply(config(None, dropped), rows)
    assert len(rows) == 2
    assert dropped == []


def test_a_policy_that_drops_nothing_deselects_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy_rows, "policy_dirs", lambda: [Path(i) for i in sorted(IDS)])
    rows = items("t.py::t[scan-secrets]", "t.py::plain")
    dropped: list[list[object]] = []
    policy_rows.apply(config(["scan-secrets"], dropped), rows)
    assert len(rows) == 2
    assert dropped == []


def test_the_option_is_registered_without_a_default() -> None:
    seen: dict[str, object] = {}
    policy_rows.add_option(SimpleNamespace(addoption=lambda name, **kw: seen.update({name: kw})))
    assert seen["--policy"]["default"] is None


def collect(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "pytest", "--collect-only", "-p", "no:cacheprovider", *args]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)


def test_pytest_keeps_one_policys_rows_and_refuses_an_unknown_policy() -> None:
    target = "tests/policies/test_every_policy.py"
    rows = [x for x in collect(target, "--policy", "block-no-verify").stdout.splitlines() if "::" in x]
    assert rows
    assert all("block-no-verify" in x or "[" not in x for x in rows)
    proc = collect(target, "--policy", "no-such-policy")
    assert proc.returncode == pytest.ExitCode.USAGE_ERROR
    assert "--policy names no policy: no-such-policy" in proc.stderr

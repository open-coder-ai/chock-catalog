"""policy_rows.py: `--policy ID` keeps a row unless it is clearly about another policy."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import policy_rows
import pytest
from trees import policy_dirs

ROOT = Path(__file__).resolve().parents[2]
IDS = {"pol-a", "pol-a-more", "pol-b"}


@pytest.mark.parametrize(
    ("nodeid", "found"),
    [
        ("t.py::test[pol-a]", {"pol-a"}),
        ("t.py::test[pol-a-more::case-1]", {"pol-a-more"}),
        ("t.py::test[pol_a_more]", {"pol-a-more"}),
        ("t.py::test[pol-b-pol-a]", set()),
        ("t.py::test[base/pol-b/x.yaml-pol-a]", {"pol-b"}),
        ("t.py::test[pol-a|pol-b]", {"pol-a", "pol-b"}),
        ("t.py::test[other]", set()),
        ("t.py::test_pol_a", set()),
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


@pytest.fixture(autouse=True)
def three_policies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy_rows, "policy_dirs", lambda: [Path(i) for i in sorted(IDS)])


def test_apply_drops_only_rows_about_other_policies() -> None:
    rows = items(
        "t.py::t[pol-a]",
        "t.py::t[pol-a-more]",
        "t.py::t[pol-b]",
        "t.py::t[no-policy-here]",
        "t.py::plain",
    )
    dropped: list[list[object]] = []
    policy_rows.apply(config(["pol-a-more"], dropped), rows)
    assert [r.nodeid for r in rows] == ["t.py::t[pol-a-more]", "t.py::t[no-policy-here]", "t.py::plain"]
    assert [r.nodeid for r in dropped[0]] == ["t.py::t[pol-a]", "t.py::t[pol-b]"]


def test_more_than_one_policy_keeps_the_rows_of_each() -> None:
    rows = items("t.py::t[pol-a]", "t.py::t[pol-b]", "t.py::t[pol-a-more]")
    policy_rows.apply(config(["pol-a", "pol-b"], []), rows)
    assert [r.nodeid for r in rows] == ["t.py::t[pol-a]", "t.py::t[pol-b]"]


def test_no_policy_option_keeps_everything_and_deselects_nothing() -> None:
    rows = items("t.py::t[pol-a]", "t.py::t[pol-b]")
    dropped: list[list[object]] = []
    policy_rows.apply(config(None, dropped), rows)
    assert len(rows) == 2
    assert dropped == []


def test_a_policy_that_drops_nothing_deselects_nothing() -> None:
    rows = items("t.py::t[pol-a]", "t.py::plain")
    dropped: list[list[object]] = []
    policy_rows.apply(config(["pol-a"], dropped), rows)
    assert len(rows) == 2
    assert dropped == []


def test_chosen_narrows_a_loop_to_the_policies_given_and_keeps_all_when_none_are() -> None:
    assert policy_rows.chosen(config(["pol-b"], []), ["pol-a", "pol-b", "pol-c"]) == ["pol-b"]
    assert policy_rows.chosen(config(["pol-a", "pol-c"], []), ["pol-a", "pol-b", "pol-c"]) == ["pol-a", "pol-c"]
    assert policy_rows.chosen(config(None, []), iter(["pol-a", "pol-b"])) == ["pol-a", "pol-b"]


def test_the_option_is_registered_without_a_default() -> None:
    seen: dict[str, object] = {}
    policy_rows.add_option(SimpleNamespace(addoption=lambda name, **kw: seen.update({name: kw})))
    assert seen["--policy"]["default"] is None


def collect(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "pytest", "--collect-only", "-p", "no:cacheprovider", *args]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)


def test_pytest_keeps_one_policys_rows_and_refuses_an_unknown_policy() -> None:
    chosen = sorted(p.name for p in policy_dirs())[0]
    target = "tests/policies/test_every_policy.py"
    rows = [x for x in collect(target, "--policy", chosen).stdout.splitlines() if "::" in x]
    assert rows
    assert all(chosen in x or "[" not in x for x in rows)
    proc = collect(target, "--policy", "no-such-policy")
    assert proc.returncode == pytest.ExitCode.USAGE_ERROR
    assert "--policy names no policy: no-such-policy" in proc.stderr

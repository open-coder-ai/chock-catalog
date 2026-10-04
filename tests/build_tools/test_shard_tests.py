"""shard_tests.py: the slices of `pytest --shard N/M` partition the suite, and a bad spec never runs less."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import shard_tests

ROOT = Path(__file__).resolve().parents[2]
NODES = [f"tests/policies/test_x.py::test_case[{n}]" for n in range(200)]


def config(spec: str | None, deselected: list[list[object]], plan: str | None = None) -> SimpleNamespace:
    def pytest_deselected(items: list[object]) -> None:
        deselected.append(items)

    hook = SimpleNamespace(pytest_deselected=pytest_deselected)
    options = {"--shard": spec, "--shard-plan": plan}
    return SimpleNamespace(getoption=lambda name: options[name], hook=hook)


@pytest.mark.parametrize(("spec", "want"), [("1/4", (1, 4)), ("4/4", (4, 4)), ("1/1", (1, 1)), ("12/30", (12, 30))])
def test_a_spec_is_slice_over_total(spec: str, want: tuple[int, int]) -> None:
    assert shard_tests.parse(spec) == want


@pytest.mark.parametrize("spec", ["", "4", "0/4", "5/4", "1/0", "a/4", "1/b", "-1/4", "1/4/4", "1/"])
def test_anything_else_is_a_usage_error(spec: str) -> None:
    with pytest.raises(pytest.UsageError, match="--shard wants N/M"):
        shard_tests.parse(spec)


def test_a_node_lands_in_one_slice_and_always_the_same_one() -> None:
    assert {shard_tests.slice_of(n, 4) for n in NODES} == {1, 2, 3, 4}
    assert shard_tests.slice_of("tests/a.py::t0", 4) == shard_tests.slice_of("tests/a.py::t0", 4) == 3
    assert {shard_tests.slice_of(n, 1) for n in NODES} == {1}


def test_the_slices_partition_the_collected_items() -> None:
    kept: list[str] = []
    for index in (1, 2, 3, 4):
        items = [SimpleNamespace(nodeid=n) for n in NODES]
        dropped: list[list[object]] = []
        shard_tests.apply(config(f"{index}/4", dropped), items)
        assert len(items) + len(dropped[0]) == len(NODES)
        kept += [i.nodeid for i in items]
    assert sorted(kept) == sorted(NODES)


def test_no_shard_option_keeps_everything_and_deselects_nothing() -> None:
    items = [SimpleNamespace(nodeid=n) for n in NODES]
    dropped: list[list[object]] = []
    shard_tests.apply(config(None, dropped), items)
    assert [i.nodeid for i in items] == NODES
    assert dropped == []


def test_a_single_shard_deselects_nothing() -> None:
    items = [SimpleNamespace(nodeid=n) for n in NODES]
    dropped: list[list[object]] = []
    shard_tests.apply(config("1/1", dropped), items)
    assert len(items) == len(NODES)
    assert dropped == []


def test_the_option_is_registered_without_a_default() -> None:
    seen: dict[str, object] = {}
    shard_tests.add_option(SimpleNamespace(addoption=lambda name, **kw: seen.update({name: kw})))
    assert seen["--shard"]["default"] is None
    assert seen["--shard-plan"]["default"] is None


def collect(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "pytest", "--collect-only", "-p", "no:cacheprovider", *args]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)


def test_pytest_accepts_the_option_and_the_two_halves_of_a_file_make_it_whole() -> None:
    target = "tests/test_repo_standards.py"
    ids = {i: [x for x in collect(target, "--shard", f"{i}/2").stdout.splitlines() if "::" in x] for i in (1, 2)}
    whole = [x for x in collect(target).stdout.splitlines() if "::" in x]
    assert whole
    assert sorted(ids[1] + ids[2]) == sorted(whole)
    assert len(set(ids[1]) & set(ids[2])) == 0


def test_pytest_refuses_a_bad_spec_rather_than_running_nothing() -> None:
    proc = collect("tests/test_repo_standards.py", "--shard", "0/2")
    assert proc.returncode == pytest.ExitCode.USAGE_ERROR
    assert "--shard wants N/M" in proc.stderr


FILES = {f"tests/policies/test_{n}.py": float(10 * (n + 1)) for n in range(6)}
BY_FILE = [SimpleNamespace(nodeid=f"{f}::t{n}") for f in FILES for n in range(5)]


def planned(tmp_path: Path, plan: object) -> str:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return str(path)


def slices(plan: str | None, total: int = 3) -> list[list[str]]:
    kept = []
    for index in range(1, total + 1):
        items = list(BY_FILE)
        shard_tests.apply(config(f"{index}/{total}", [], plan), items)
        kept.append([i.nodeid for i in items])
    return kept


def test_a_planned_file_stays_whole_in_its_slice_and_the_slices_partition_the_suite(tmp_path: Path) -> None:
    names = sorted(FILES)
    plan = {"shards": 3, "assignment": {n: i % 3 + 1 for i, n in enumerate(names)}, "split": []}
    kept = slices(planned(tmp_path, plan))
    assert sorted(n for k in kept for n in k) == sorted(i.nodeid for i in BY_FILE)
    for index, nodes in enumerate(kept, start=1):
        assert {n.partition("::")[0] for n in nodes} == {f for f, s in plan["assignment"].items() if s == index}


def test_a_file_the_plan_splits_or_does_not_know_keeps_the_hash_of_its_tests(tmp_path: Path) -> None:
    names = sorted(FILES)
    plan = {"shards": 3, "assignment": {names[0]: 1}, "split": [names[1]]}
    kept = slices(planned(tmp_path, plan))
    assert sorted(n for k in kept for n in k) == sorted(i.nodeid for i in BY_FILE)
    hashed = {i.nodeid: shard_tests.slice_of(i.nodeid, 3) for i in BY_FILE if not i.nodeid.startswith(names[0])}
    for index, nodes in enumerate(kept, start=1):
        assert {n for n in nodes if not n.startswith(names[0])} == {n for n, s in hashed.items() if s == index}


def test_an_empty_plan_is_the_hash_split(tmp_path: Path) -> None:
    empty = {"shards": 3, "assignment": {}, "split": []}
    assert slices(planned(tmp_path, empty)) == slices(None)


def test_a_plan_for_another_number_of_slices_is_an_error(tmp_path: Path) -> None:
    plan = planned(tmp_path, {"shards": 4, "assignment": {}, "split": []})
    with pytest.raises(pytest.UsageError, match="plan for 4 shards, not 3"):
        slices(plan)


@pytest.mark.parametrize("bad", ["absent.json", "garbled.json"])
def test_a_missing_or_garbled_plan_is_an_error_not_a_different_split(tmp_path: Path, bad: str) -> None:
    (tmp_path / "garbled.json").write_text("{", encoding="utf-8")
    with pytest.raises(pytest.UsageError, match="is not a shard plan"):
        slices(str(tmp_path / bad))


def test_the_options_register_when_a_value_is_a_file_that_exists() -> None:
    """CI passes `--shard-plan shard-plan.json`; pytest reads an existing file there as a path."""
    proc = collect("--shard", "1/2", "--shard-plan", "pyproject.toml")
    assert "unrecognized arguments" not in proc.stderr
    assert proc.returncode == pytest.ExitCode.USAGE_ERROR
    assert "pyproject.toml is not a shard plan" in proc.stderr

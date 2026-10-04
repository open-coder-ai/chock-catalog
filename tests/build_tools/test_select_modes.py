"""select_tests.py: generated files never force a full run, and --matrix and --residual cut a PR into policy jobs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import select_tests
from build_tools.selkit import STANDARDS, commit, write


@pytest.mark.parametrize("generated", sorted(select_tests.GENERATED))
def test_a_generated_file_runs_no_test_of_its_own(tree: Path, generated: str) -> None:
    write(tree, generated)
    assert select_tests.select(tree, [generated]) == (False, set(), {STANDARDS})
    assert select_tests.select(tree, ["base/beta/manifest.yaml", generated])[1] == {"beta"}


def test_a_deleted_generated_file_or_a_generator_is_full(tree: Path) -> None:
    assert select_tests.select(tree, ["docs/assets/social-preview.svg"])[0]
    write(tree, "docs/figures/make_family.py")
    assert select_tests.select(tree, ["docs/figures/make_family.py"])[0]


def test_no_test_of_the_catalog_reads_a_generated_file() -> None:
    """GENERATED claims no test reads them; one that starts to would be skipped on the PR that changes it."""
    names = {Path(rel).name for rel in select_tests.GENERATED}
    tests = sorted(p for p in (select_tests.ROOT / "tests").rglob("*.py") if not p.name.startswith("test_select_"))
    assert [t.name for t in tests if any(n in t.read_text(encoding="utf-8") for n in names)] == []
    assert all((select_tests.ROOT / rel).is_file() for rel in select_tests.GENERATED)


def test_the_matrix_is_one_job_per_policy_and_policy_built_on_it(tree: Path) -> None:
    write(tree, "base/alpha/evals/suite.yaml")
    assert select_tests.matrix(tree, ["base/alpha/evals/suite.yaml"]) == [
        {
            "id": "alpha",
            "path": "base/alpha",
            "tests": sorted(select_tests.proving_tests(tree, {"alpha"})),
        },
        {
            "id": "beta",
            "path": "base/beta",
            "tests": ["tests/policies/test_names_beta.py", "tests/policies/test_walks.py"],
        },
    ]


def test_a_policy_in_another_tree_has_its_tree_in_its_path(tree: Path) -> None:
    write(tree, "compliance/gamma/evals/suite.yaml")
    (job,) = select_tests.matrix(tree, ["compliance/gamma/evals/suite.yaml"])
    assert (job["id"], job["path"]) == ("gamma", "compliance/gamma")


def test_a_change_naming_no_policy_is_an_empty_matrix_and_the_standards_test(tree: Path) -> None:
    write(tree, "docs/assets/social-preview.svg")
    assert select_tests.matrix(tree, ["docs/assets/social-preview.svg"]) == []
    assert select_tests.residual(tree, ["docs/assets/social-preview.svg"]) == [STANDARDS]


def test_the_residual_is_the_changed_and_always_run_tests(tree: Path) -> None:
    write(tree, "base/beta/evals/suite.yaml")
    assert select_tests.residual(tree, ["base/beta/evals/suite.yaml"]) == [STANDARDS]
    assert select_tests.residual(tree, ["base/beta/evals/suite.yaml", "tests/orphans/test_names_nothing.py"]) == [
        "tests/orphans/test_names_nothing.py",
        STANDARDS,
    ]


def test_a_changed_test_is_in_the_residual_even_when_a_policy_job_owns_it(tree: Path) -> None:
    """A policy job runs it only under --policy; the targeted run must also run it whole."""
    write(tree, "base/beta/evals/suite.yaml")
    changed = ["base/beta/evals/suite.yaml", "tests/policies/test_walks.py", "tests/policies/test_names_beta.py"]
    (job,) = [j for j in select_tests.matrix(tree, changed) if j["id"] == "beta"]
    assert {"tests/policies/test_walks.py", "tests/policies/test_names_beta.py"} <= set(job["tests"])
    assert select_tests.residual(tree, changed) == [
        "tests/policies/test_names_beta.py",
        "tests/policies/test_walks.py",
        STANDARDS,
    ]


def test_a_test_that_imports_a_changed_private_kit_is_in_the_residual(tree: Path) -> None:
    assert select_tests.residual(tree, ["tests/policies/gammakit.py"]) == ["tests/policies/test_via_kit.py", STANDARDS]


@pytest.mark.parametrize("changed", [[], ["pyproject.toml"], ["base/alpha/manifest.yaml", "tools/trees.py"]])
def test_matrix_and_residual_are_none_whenever_select_is_full(tree: Path, changed: list[str]) -> None:
    assert select_tests.matrix(tree, changed) is None
    assert select_tests.residual(tree, changed) is None


def test_more_policies_than_the_job_cap_is_one_full_run(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tree, "base/alpha/evals/suite.yaml")
    assert select_tests.select(tree, ["base/alpha/evals/suite.yaml"])[0] is False
    monkeypatch.setattr(select_tests, "MAX_POLICY_JOBS", 1)
    assert select_tests.select(tree, ["base/alpha/evals/suite.yaml"]) == (True, set(), set())
    assert select_tests.matrix(tree, ["base/alpha/evals/suite.yaml"]) is None


def test_the_job_cap_is_eight() -> None:
    assert select_tests.MAX_POLICY_JOBS == 8


def test_main_prints_the_matrix_as_json_and_the_residual_one_file_a_line(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    commit(repo, "base/beta/evals/suite.yaml", "x\n")
    assert select_tests.main(["main", "--matrix"]) == 0
    assert [job["id"] for job in json.loads(capsys.readouterr().out)] == ["beta"]
    assert select_tests.main(["main", "--residual"]) == 0
    assert capsys.readouterr().out.splitlines() == [STANDARDS]


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize("mode", ["--matrix", "--residual", "--policies"])
def test_main_prints_full_in_every_mode_when_it_cannot_tell(capsys: pytest.CaptureFixture[str], mode: str) -> None:
    assert select_tests.main(["no-such-ref", mode]) == 0
    out = capsys.readouterr()
    assert out.out.strip() == select_tests.FULL
    assert "running everything" in out.err


def test_the_modes_are_exclusive() -> None:
    with pytest.raises(SystemExit):
        select_tests.main(["main", "--matrix", "--residual"])

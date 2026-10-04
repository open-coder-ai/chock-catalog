"""select_plan.py: CI's per-policy jobs; and the generated images, which never force a full run."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import select_plan
import select_tests
from build_tools.selkit import STANDARDS, commit, write


@pytest.mark.parametrize("image", sorted(select_tests.IMAGES))
def test_a_generated_image_runs_no_test_of_its_own(tree: Path, image: str) -> None:
    write(tree, image)
    assert select_tests.select(tree, [image]) == (False, set(), {STANDARDS})
    assert select_tests.select(tree, ["base/beta/manifest.yaml", image])[1] == {"beta"}


def test_a_deleted_image_or_an_image_generator_is_full(tree: Path) -> None:
    assert select_tests.select(tree, ["docs/assets/social-preview.svg"])[0]
    write(tree, "docs/figures/make_family.py")
    assert select_tests.select(tree, ["docs/figures/make_family.py"])[0]


def test_the_catalog_reads_no_generated_image_in_a_test() -> None:
    """IMAGES claims no test reads them; a test that starts to would be skipped on the PR that changes one."""
    names = {Path(image).name for image in select_tests.IMAGES}
    tests = sorted(p for p in (select_tests.ROOT / "tests").rglob("*.py") if not p.name.startswith("test_select_"))
    assert [t.name for t in tests if any(n in t.read_text(encoding="utf-8") for n in names)] == []
    assert all((select_tests.ROOT / image).is_file() for image in select_tests.IMAGES)


def test_the_plan_is_one_job_per_policy_and_dependent(tree: Path) -> None:
    write(tree, "base/alpha/evals/suite.yaml")
    layout = select_plan.plan(tree, ["base/alpha/evals/suite.yaml"])
    assert layout == {
        "full": False,
        "policies": [
            {
                "policy": "alpha",
                "folder": "base/alpha",
                "implementations": "base/alpha/implementations",
                "omit": "base/alpha/implementations/chock_lib/**",
                "transcript": True,
                "tests": " ".join(sorted(select_tests.proving_tests(tree, {"alpha"}))),
            },
            {
                "policy": "beta",
                "folder": "base/beta",
                "implementations": "base/beta/implementations",
                "omit": "",
                "transcript": False,
                "tests": "tests/policies/test_names_beta.py tests/policies/test_walks.py",
            },
        ],
        "tests": STANDARDS,
    }


def test_a_policy_shipping_no_python_has_no_coverage_gate(tree: Path) -> None:
    write(tree, "compliance/gamma/evals/suite.yaml")
    (job,) = select_plan.plan(tree, ["compliance/gamma/evals/suite.yaml"])["policies"]
    assert (job["folder"], job["implementations"], job["omit"]) == ("compliance/gamma", "", "")


def test_a_changed_test_no_policy_job_runs_runs_beside_them_and_one_a_job_runs_does_not_twice(tree: Path) -> None:
    write(tree, "base/beta/evals/suite.yaml")
    layout = select_plan.plan(tree, ["base/beta/evals/suite.yaml", "tests/orphans/test_names_nothing.py"])
    assert [job["policy"] for job in layout["policies"]] == ["beta"]
    assert layout["tests"] == f"tests/orphans/test_names_nothing.py {STANDARDS}"
    layout = select_plan.plan(tree, ["base/beta/evals/suite.yaml", "tests/policies/test_walks.py"])
    assert layout["tests"] == STANDARDS


@pytest.mark.parametrize("changed", [[], ["pyproject.toml"], ["base/alpha/manifest.yaml", "tools/trees.py"]])
def test_the_plan_is_full_whenever_select_is(tree: Path, changed: list[str]) -> None:
    assert select_plan.plan(tree, changed) == {"full": True}


def test_more_policies_than_the_job_cap_is_one_full_run(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tree, "base/alpha/evals/suite.yaml")
    monkeypatch.setattr(select_plan, "MAX_POLICY_JOBS", 1)
    assert select_plan.plan(tree, ["base/alpha/evals/suite.yaml"]) == {"full": True}


def test_main_prints_the_plan_as_json(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    commit(repo, "base/beta/evals/suite.yaml", "x\n")
    assert select_plan.main(["main"]) == 0
    layout = json.loads(capsys.readouterr().out)
    assert [job["policy"] for job in layout["policies"]] == ["beta"]


@pytest.mark.usefixtures("repo")
def test_main_plans_a_full_run_whenever_it_cannot_tell(capsys: pytest.CaptureFixture[str]) -> None:
    assert select_plan.main(["no-such-ref"]) == 0
    out = capsys.readouterr()
    assert json.loads(out.out) == {"full": True}
    assert "running everything" in out.err


def test_run_as_a_script_it_plans_a_full_run_for_a_base_it_cannot_find() -> None:
    proc = subprocess.run(
        [sys.executable, str(Path(select_plan.__file__)), "no-such-ref"], capture_output=True, text=True, check=True
    )
    assert json.loads(proc.stdout) == {"full": True}

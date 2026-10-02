"""tools/check_workflows.py: no fork-secret triggers, and no framework checkout that is not proven to be the pin."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import check_workflows
import pytest
import yaml
from trees import ROOT

CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
ENV_PIN = "${{ env.FRAMEWORK_REF }}"
INPUT_PIN = "${{ inputs.framework_ref }}"
READ = {"name": "Read the framework pin", "run": "python3 -I tools/framework_ref.py read"}
CHECK = {"run": "python3 -I tools/framework_ref.py check", "env": {"FRAMEWORK_REF": INPUT_PIN}}
VERIFY = {"run": "python3 -I tools/framework_ref.py verify .framework"}
INSTALL = {"run": "pip install ./.framework"}
SHA = "5c9350738729a2cf1c40f5851628384751cae484"


def _checkout(ref: str = ENV_PIN, **extra: str) -> dict:
    return {"uses": CHECKOUT, "with": {"repository": "open-coder-ai/chock", "ref": ref, "path": ".framework", **extra}}


def _problems(*steps: dict) -> list[str]:
    return check_workflows.framework_checkouts("w.yml", {"jobs": {"j": {"steps": list(steps)}}})


def test_this_repos_workflows_pass(capsys) -> None:
    assert check_workflows.main() == 0
    assert "workflow(s) checked" in capsys.readouterr().out


def test_every_framework_checkout_here_is_found_and_guarded() -> None:
    """The real workflows: each FRAMEWORK_REF checkout is seen by the rule, and passes it."""
    found = 0
    for path in check_workflows.WORKFLOWS:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert check_workflows.framework_checkouts(path.name, workflow) == []
        for job in (workflow.get("jobs") or {}).values():
            found += sum(
                "framework" in str((s.get("with") or {}).get("ref", "")).lower() for s in job.get("steps") or []
            )
    assert found >= 8


@pytest.mark.parametrize(
    "key", ["PATH", "PYTHONPATH", "pythonhome", "GIT_DIR", "LD_LIBRARY_PATH", "LD_PRELOAD", "HOME", "XDG_CONFIG_HOME"]
)
@pytest.mark.parametrize("where", ["workflow", "job"])
def test_env_that_redirects_git_or_python_fails(key: str, where: str) -> None:
    job = {"steps": [READ, _checkout(), VERIFY]}
    workflow = {"jobs": {"j": job}}
    (workflow if where == "workflow" else job)["env"] = {key: ".framework", "FORCE_COLOR": "1"}
    problems = check_workflows.framework_checkouts("w.yml", workflow)
    assert any(f"[{key!r}]" in p for p in problems), problems


def test_an_expression_valued_env_fails() -> None:
    workflow = {"jobs": {"j": {"env": "${{ fromJSON(inputs.env) }}", "steps": [READ, _checkout(), VERIFY]}}}
    assert any("fromJSON" in p for p in check_workflows.framework_checkouts("w.yml", workflow))


def test_ordinary_env_around_a_framework_checkout_passes() -> None:
    job = {"env": {"pip_no_input": "1", "TZ": "UTC"}, "steps": [READ, _checkout(), VERIFY]}
    assert check_workflows.framework_checkouts("w.yml", {"env": {"FORCE_COLOR": "1"}, "jobs": {"j": job}}) == []


def test_defaults_run_around_a_framework_checkout_fails() -> None:
    for where in ("workflow", "job"):
        job = {"steps": [READ, _checkout(), VERIFY]}
        workflow = {"jobs": {"j": job}}
        (workflow if where == "workflow" else job)["defaults"] = {"run": {"shell": "true {0}"}}
        assert any("defaults.run" in p for p in check_workflows.framework_checkouts("w.yml", workflow))
    clean = {"defaults": {"run": {}}, "jobs": {"j": {"defaults": {"run": None}, "steps": [READ, _checkout(), VERIFY]}}}
    assert check_workflows.framework_checkouts("w.yml", clean) == []


@pytest.mark.parametrize(
    "steps",
    [
        (READ, _checkout(), VERIFY, INSTALL),
        (READ, INSTALL, _checkout(), VERIFY),
        (CHECK, _checkout(INPUT_PIN), {**VERIFY, "env": {"FRAMEWORK_REF": INPUT_PIN}}),
        ({"uses": CHECKOUT, "with": {"persist-credentials": False}}, READ, _checkout(), VERIFY),
        ({"uses": CHECKOUT, "with": {"repository": "open-coder-ai/chock", "ref": "main"}},),
        ({"uses": CHECKOUT, "with": {"repository": "open-coder-ai/chock", "ref": "release/1.x"}},),
        (
            READ,
            {"uses": CHECKOUT, "with": {"repository": "o/r", "ref": ENV_PIN}},
            {"run": "python3 -I tools/framework_ref.py verify ."},
        ),
    ],
)
def test_guarded_checkouts_pass(steps: tuple[dict, ...]) -> None:
    assert _problems(*steps) == []


@pytest.mark.parametrize(
    ("steps", "needle"),
    [
        ((_checkout(), VERIFY), "no earlier step refuses a non-SHA ref"),
        ((_checkout(), READ, VERIFY), "no earlier step refuses a non-SHA ref"),
        ((READ, _checkout()), "the next step is not `python3 -I tools/framework_ref.py verify .framework`"),
        ((READ, _checkout(), INSTALL, VERIFY), "the next step is not"),
        ((READ, _checkout(), {"run": "python3 -I tools/framework_ref.py verify ."}), "the next step is not"),
        (
            (READ, _checkout(), {"run": "python3 -I tools/framework_ref.py verify .framework || true"}),
            "the next step is",
        ),
        ((READ, _checkout(), {**VERIFY, "if": "false"}), "can be skipped"),
        ((READ, _checkout(), {**VERIFY, "continue-on-error": True}), "can be skipped"),
        ((READ, _checkout(), {**VERIFY, "env": {"FRAMEWORK_REF": INPUT_PIN}}), "not the ref checked out"),
        ((READ, _checkout(INPUT_PIN), {**VERIFY, "env": {"FRAMEWORK_REF": INPUT_PIN}}), "no earlier step refuses"),
        (({**CHECK, "env": {}}, _checkout(INPUT_PIN), {**VERIFY, "env": {"FRAMEWORK_REF": INPUT_PIN}}), "refuses"),
        ((CHECK, _checkout(INPUT_PIN), VERIFY), "not the ref checked out"),
        ((READ, _checkout("${{ env.FRAMEWORK_REF_OVERRIDE }}"), VERIFY), "its ref must be one of"),
        ((READ, _checkout(f"{ENV_PIN}-x"), VERIFY), "its ref must be one of"),
        (
            ({"uses": CHECKOUT, "with": {"repository": "open-coder-ai/chock", "ref": "${{ env.CHOCK_SHA }}"}},),
            "literal",
        ),
        (
            ({"uses": CHECKOUT, "with": {"repository": "open-coder-ai/chock"}},),
            "the default ref of open-coder-ai/chock",
        ),
        (
            ({"uses": CHECKOUT, "with": {"repository": "open-coder-ai/chock", "ref": SHA}},),
            "goes through FRAMEWORK_REF",
        ),
        (({"uses": CHECKOUT, "with": {"repository": "open-coder-ai/chock", "ref": SHA[:12].upper()}},), "goes through"),
        (({"uses": "Actions/Checkout@v4", "with": {"repository": "o/r", "ref": ENV_PIN}},), "no earlier step refuses"),
        (
            ({"uses": CHECKOUT, "with": {"Repository": "o/r", "Ref": ENV_PIN, "Path": ".framework"}},),
            "the next step is",
        ),
        ((READ, _checkout(), {**VERIFY, "shell": "true {0}"}), "sets ['shell']"),
        ((READ, _checkout(), {**VERIFY, "working-directory": ".framework"}), "sets ['working-directory']"),
        ((READ, _checkout(), {**VERIFY, "env": {"GIT_DIR": "/elsewhere/.git"}}), "sets ['GIT_DIR']"),
        ((READ, _checkout(clean="false"), VERIFY), "`clean: false`"),
        (({**READ, "if": "false"}, _checkout(), VERIFY), "no earlier step refuses"),
        (
            (
                {**CHECK, "continue-on-error": True},
                _checkout(INPUT_PIN),
                {**VERIFY, "env": {"FRAMEWORK_REF": INPUT_PIN}},
            ),
            "refuses",
        ),
    ],
)
def test_unguarded_checkouts_fail(steps: tuple[dict, ...], needle: str) -> None:
    problems = _problems(*steps)
    assert problems
    assert all(p.startswith("w.yml job 'j' checks out") for p in problems)
    assert any(needle in p for p in problems), problems


def test_jobs_without_steps_and_workflows_without_jobs_pass() -> None:
    assert check_workflows.framework_checkouts("w.yml", {"jobs": {"call": {"uses": "./.github/workflows/x.yml"}}}) == []
    assert check_workflows.framework_checkouts("w.yml", {"on": "push"}) == []


def _workflow(tmp_path: Path, body: dict) -> Path:
    path = tmp_path / "w.yml"
    path.write_text(yaml.safe_dump(body), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("on", "unsafe"),
    [
        ({"pull_request_target": None}, True),
        (["push", "workflow_run"], True),
        ("pull_request_target", True),
        ({"pull_request": None}, False),
        ("push", False),
    ],
)
def test_triggers_that_hand_forks_secrets_fail(tmp_path: Path, on: object, unsafe: bool) -> None:
    problems = check_workflows.check(_workflow(tmp_path, {"on": on, "jobs": {}}))
    assert bool(problems) is unsafe


def test_checking_out_a_contributors_head_fails(tmp_path: Path) -> None:
    step = {"uses": CHECKOUT, "with": {"ref": "${{ github.event.pull_request.head.sha }}"}}
    problems = check_workflows.check(_workflow(tmp_path, {"on": "push", "jobs": {"j": {"steps": [step]}}}))
    assert problems == ["w.yml checks out github.event.pull_request.head.sha, which a contributor controls."]


def test_main_reports_each_problem(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    bad = _workflow(tmp_path, {"on": "push", "jobs": {"j": {"steps": [_checkout(), VERIFY]}}})
    monkeypatch.setattr(check_workflows, "WORKFLOWS", [bad])
    assert check_workflows.main() == 1
    assert "no earlier step refuses a non-SHA ref" in capsys.readouterr().err


def test_main_refuses_when_there_are_no_workflows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(check_workflows, "WORKFLOWS", [])
    assert check_workflows.main() == 1


def test_runs_as_a_script() -> None:
    cmd = [sys.executable, str(ROOT / "tools" / "check_workflows.py")]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr

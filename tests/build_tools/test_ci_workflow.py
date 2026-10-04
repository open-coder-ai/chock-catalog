"""ci.yml: it reports its required checks in the merge queue, and no job can run past its time budget."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from trees import ROOT

CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
JOBS = CI["jobs"]
#: `on` is a YAML 1.1 boolean to PyYAML.
TRIGGERS = CI.get("on", CI.get(True))
REQUIRED = ("policies", "tests", "dco")
QUICK = ("dco", "no-private-data", "scope", "generated")
HEAVY = ("tests-shard", "tests-policy")
#: A job that hits its budget fails the run; no job may be given more than this.
BUDGET_CEILING = 9
GIT = shutil.which("git") or "git"
BASH = shutil.which("bash") or "bash"
SIGNED = "Signed-off-by: A <a@users.noreply.github.com>"


def test_the_merge_queue_triggers_ci() -> None:
    assert "merge_group" in TRIGGERS


@pytest.mark.parametrize("job", REQUIRED)
def test_a_required_check_reports_on_a_merge_group_run(job: str) -> None:
    condition = str(JOBS[job].get("if", "always()"))
    assert condition == "always()" or "merge_group" in condition


def test_a_run_is_full_unless_it_is_a_pull_request() -> None:
    script = next(s["run"] for s in JOBS["scope"]["steps"] if s.get("id") == "scope")
    assert "full=true\n" in script
    assert script.index("full=true\n") < script.index('"$EVENT_NAME" = pull_request')
    assert script.count("full=false") == 1


def test_every_job_has_a_time_budget_within_the_ceiling() -> None:
    budgets = {name: job.get("timeout-minutes") for name, job in JOBS.items()}
    assert all(isinstance(b, int) and 0 < b <= BUDGET_CEILING for b in budgets.values()), budgets
    assert all(budgets[name] == BUDGET_CEILING for name in HEAVY)
    assert all(budgets[name] <= 3 for name in QUICK)


def commit(repo: Path, message: str) -> str:
    env = {
        "GIT_AUTHOR_NAME": "A",
        "GIT_AUTHOR_EMAIL": "a@x.io",
        "GIT_COMMITTER_NAME": "A",
        "GIT_COMMITTER_EMAIL": "a@x.io",
    }
    git = [GIT, "-c", "commit.gpgsign=false", "-C", str(repo)]
    subprocess.run([*git, "commit", "--allow-empty", "-qm", message], check=True, env=env)
    return subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()


def dco(repo: Path, base_sha: str) -> subprocess.CompletedProcess[str]:
    """The DCO step's script as a merge-group run gives it its inputs: no base ref, the queue's base commit."""
    script = next(s["run"] for s in JOBS["dco"]["steps"] if "Signed-off-by" in s.get("name", ""))
    env = {"EVENT_NAME": "merge_group", "BASE_SHA": base_sha, "BASE_REF": "", "PATH": "/usr/bin:/bin"}
    return subprocess.run([BASH, "-c", script], cwd=repo, env=env, capture_output=True, text=True, check=False)


def test_dco_on_a_merge_group_reads_the_queue_base_sha(tmp_path: Path) -> None:
    subprocess.run([GIT, "init", "-q", str(tmp_path)], check=True)
    base = commit(tmp_path, "base")
    commit(tmp_path, f"signed\n\n{SIGNED}")
    assert dco(tmp_path, base).returncode == 0
    unsigned = commit(tmp_path, "unsigned")
    refused = dco(tmp_path, base)
    assert refused.returncode == 1
    assert unsigned in refused.stdout
    assert dco(tmp_path, unsigned).returncode == 0

"""ci.yml: it reports its required checks in the merge queue, and no job can run past its time budget."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest
import shard_tests
import yaml
from chock.lifecycle import CHECKS
from trees import ROOT, policy_dirs

CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
JOBS = CI["jobs"]
#: `on` is a YAML 1.1 boolean to PyYAML.
TRIGGERS = CI.get("on", CI.get(True))
REQUIRED = ("policies", "tests", "dco")
QUICK = ("dco", "no-private-data", "scope", "generated")
HEAVY = ("tests-shard", "tests-policy", "staged-adopter")
#: A job that hits its budget fails the run; no job may be given more than this.
BUDGET_CEILING = 9
#: windows-adopter replays every installed eval case on a Windows runner: longest 17:00 of 14 runs from 2026-11-02 to
#: 2026-11-05 (41552867589, 41950172932, both at the old budget), plus half again, rounded up.
WINDOWS_ADOPTER_BUDGET = 26
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
    ceilings = {name: WINDOWS_ADOPTER_BUDGET if name == "windows-adopter" else BUDGET_CEILING for name in budgets}
    assert all(isinstance(b, int) and 0 < b <= ceilings[name] for name, b in budgets.items()), budgets
    assert budgets["windows-adopter"] == WINDOWS_ADOPTER_BUDGET
    assert all(budgets[name] == BUDGET_CEILING for name in HEAVY)
    assert all(budgets[name] <= 3 for name in QUICK)


STAGED = JOBS["staged-adopter"]
#: `chock check` skips these on the staged adopter: it has no spec/enforcement-matrix.md and is given no --base.
SKIPPED_WHEN_STAGED = {"matrix", "mechanisms", "baseline"}


def staged_step(name: str) -> dict:
    return next(s for s in STAGED["steps"] if s.get("name", "").startswith(name))


#: chock.eval.suites as the replay step imports it, over the policies and case counts in cases.json beside it.
STUB = """import json
from pathlib import Path
from types import SimpleNamespace

CASES = json.loads((Path(__file__).parent / "cases.json").read_text(encoding="utf-8"))


def discover_policies(repo):
    return [SimpleNamespace(id=pid, cases=lambda n=n: [None] * n) for pid, n in CASES.items()]
"""


def pack(stub: Path, cases: dict[str, int], shard: int, shards: int) -> list[str]:
    """The ids the replay step's own Python prints for `shard` of `shards`, over policies with these case counts."""
    script = staged_step("Replay the evals")["run"]
    source = script.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    suites = stub / "chock" / "eval"
    suites.mkdir(parents=True, exist_ok=True)
    for package in (stub / "chock", suites):
        (package / "__init__.py").write_text("", encoding="utf-8")
    (suites / "suites.py").write_text(STUB, encoding="utf-8")
    (suites / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
    run = subprocess.run(
        [sys.executable, "-", str(shard), str(shards), str(stub)],
        input=source,
        env={"PYTHONPATH": str(stub), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    )
    return run.stdout.split()


def catalog_cases() -> dict[str, int]:
    """Each published policy's id and its eval case count, as the staged adopter has them."""
    found = {}
    for directory in policy_dirs():
        manifest = yaml.safe_load((directory / "manifest.yaml").read_text(encoding="utf-8")) or {}
        suite = directory / "evals" / "suite.yaml"
        data = yaml.safe_load(suite.read_text(encoding="utf-8")) if suite.exists() else None
        found[str(manifest.get("id") or directory.name)] = len(((data or {}).get("suite") or {}).get("cases") or [])
    return found


def test_the_staged_adopter_is_a_check_cell_and_eval_shards() -> None:
    shards = STAGED["strategy"]["matrix"]["shard"]
    assert shards == list(range(len(shards)))
    assert len(shards) > 2
    assert STAGED["strategy"]["fail-fast"] is False
    replay = staged_step("Replay the evals")
    assert replay["env"] == {"SHARD": "${{ matrix.shard }}", "JOBS": "${{ strategy.job-total }}"}
    assert '"$((JOBS - 1))"' in replay["run"]
    assert "matrix.shard != 0" in replay["if"]
    assert "matrix.shard == 0" in staged_step("Validate the staged policies")["if"]
    assert "matrix.shard == 0" in staged_step("OWASP ASI coverage claim")["if"]
    assert "chock compliance report --framework owasp_asi" in staged_step("OWASP ASI coverage claim")["run"]


def test_the_check_cell_runs_every_check_but_the_evals() -> None:
    run = staged_step("Validate the staged policies")["run"]
    only = set(run.split("--only ", 1)[1].split()[0].split(","))
    assert only == set(CHECKS) - {"evals"} - SKIPPED_WHEN_STAGED


@pytest.mark.parametrize("shards", [1, 2, 3, 4, 7])
def test_every_staged_policy_is_replayed_by_exactly_one_shard(shards: int, tmp_path: Path) -> None:
    cases = catalog_cases()
    assert len(cases) == len(policy_dirs())
    replayed = Counter(pid for shard in range(1, shards + 1) for pid in pack(tmp_path, cases, shard, shards))
    assert set(replayed) == set(cases)
    assert set(replayed.values()) == {1}


@pytest.mark.parametrize("shard", [1, 2, 3])
def test_a_shard_fails_when_no_policy_is_discovered(shard: int, tmp_path: Path) -> None:
    with pytest.raises(subprocess.CalledProcessError) as refused:
        pack(tmp_path, {}, shard, 3)
    assert refused.value.returncode == 1
    assert "No policies found" in refused.value.stderr


def test_each_matrix_shard_replays_a_part_of_the_catalog(tmp_path: Path) -> None:
    shards = len(STAGED["strategy"]["matrix"]["shard"]) - 1
    cases = catalog_cases()
    replayed = [pack(tmp_path, cases, shard, shards) for shard in range(1, shards + 1)]
    assert sorted(pid for ids in replayed for pid in ids) == sorted(cases)
    assert all(replayed)


@pytest.mark.parametrize("bad", ["failure", "cancelled", "skipped"])
def test_policies_fails_unless_every_staged_adopter_cell_succeeds(bad: str) -> None:
    gate = JOBS["policies"]
    assert "staged-adopter" in gate["needs"]
    assert gate["if"] == "always()"
    step = gate["steps"][0]
    assert step["env"]["RESULTS"] == "${{ join(needs.*.result, ' ') }}"

    def gate_exit(results: list[str]) -> int:
        env = {"RESULTS": " ".join(results), "PATH": "/usr/bin:/bin"}
        return subprocess.run([BASH, "-c", step["run"]], env=env, capture_output=True, check=False).returncode

    needed = ["success"] * len(gate["needs"])
    assert gate_exit(needed) == 0
    needed[gate["needs"].index("staged-adopter")] = bad
    assert gate_exit(needed) == 1


SCOPE_SCRIPT = next(s["run"] for s in JOBS["scope"]["steps"] if s.get("id") == "scope")
POLICY_JOB = JOBS["tests-policy"]
POLICY_STEP = next(s for s in POLICY_JOB["steps"] if s.get("name", "").startswith("Tests of this policy"))
GATE_STEP = next(s for s in JOBS["tests"]["steps"] if s.get("name") == "Every test job this run needed passed")
COMBINE_STEP = next(s for s in JOBS["tests"]["steps"] if s.get("name", "").startswith("Combine each split policy"))
#: Policy jobs as `select_tests.py --matrix` prints them, the heavy one among them.
JOBS_IN = [
    {"id": "protect-agent-config", "path": "base/protect-agent-config", "tests": ["tests/a.py", "tests/b.py"]},
    {"id": "verify-mcp-allowlist", "path": "base/verify-mcp-allowlist", "tests": ["tests/c.py"]},
]


def policy_cells(jobs: list[dict], tmp_path: Path) -> list[dict]:
    """The tests-policy matrix the scope step's own Python makes from these policy jobs."""
    source = SCOPE_SCRIPT.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    (tmp_path / "matrix.out").write_text(json.dumps(jobs), encoding="utf-8")
    run = subprocess.run(
        [sys.executable, "-I", "-", str(tmp_path / "matrix.out")],
        input=source,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(run.stdout)


def test_the_heavy_policy_is_cut_into_parts_and_the_rest_stay_whole(tmp_path: Path) -> None:
    cells = policy_cells(JOBS_IN, tmp_path)
    heavy = [c for c in cells if c["id"] == "protect-agent-config"]
    assert len(heavy) >= 3
    assert sorted(c["part"] for c in heavy) == list(range(1, len(heavy) + 1))
    assert {c["parts"] for c in heavy} == {len(heavy)}
    assert all({k: c[k] for k in ("id", "path", "tests")} == JOBS_IN[0] for c in heavy)
    light = [c for c in cells if c["id"] == "verify-mcp-allowlist"]
    assert light == [{**JOBS_IN[1], "part": 1, "parts": 1, "name": "verify-mcp-allowlist"}]
    assert len({c["name"] for c in cells}) == len(cells)
    assert policy_cells([], tmp_path) == []


def test_every_test_of_a_split_policy_runs_in_exactly_one_part(tmp_path: Path) -> None:
    run = POLICY_STEP["run"]
    assert POLICY_STEP["env"]["PART"] == "${{ matrix.part }}"
    assert POLICY_STEP["env"]["PARTS"] == "${{ matrix.parts }}"
    assert run.count('--shard "$PART/$PARTS"') == 2
    assert "--shard-plan" not in run
    assert POLICY_JOB["name"] == "tests-policy (${{ matrix.name }})"
    nodes = [f"tests/a.py::test_case[{n}]" for n in range(500)] + [f"tests/b.py::test_rule[{n}]" for n in range(500)]
    for cells in (
        [c for c in policy_cells(JOBS_IN, tmp_path) if c["id"] == policy]
        for policy in ("protect-agent-config", "verify-mcp-allowlist")
    ):
        ran: Counter[str] = Counter()
        for cell in cells:
            items = [SimpleNamespace(nodeid=n) for n in nodes]
            options = {"--shard": f"{cell['part']}/{cell['parts']}", "--shard-plan": None}
            hook = SimpleNamespace(pytest_deselected=lambda **_: None)
            shard_tests.apply(SimpleNamespace(getoption=options.get, hook=hook), items)
            assert items or cell["parts"] > len(nodes)
            ran.update(i.nodeid for i in items)
        assert set(ran) == set(nodes)
        assert set(ran.values()) == {1}


def test_a_split_policy_part_leaves_its_coverage_for_the_tests_job() -> None:
    run = POLICY_STEP["run"]
    whole, parts = run.split('if [ "$PARTS" = 1 ]; then', 1)[1].split("exit 0", 1)
    assert "--cov-fail-under=100" in whole
    assert 'COVERAGE_FILE="$RUNNER_TEMP/policy-coverage/cov.$POLICY.$PART"' in parts
    upload = next(s for s in POLICY_JOB["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    assert upload["if"] == "matrix.parts > 1"
    assert upload["with"]["if-no-files-found"] == "error"
    assert "--fail-under=100" in COMBINE_STEP["run"]
    assert COMBINE_STEP["env"] == {"SPLIT": "${{ needs.scope.outputs.split }}"}


def test_the_combine_step_fails_when_a_part_left_no_coverage(tmp_path: Path) -> None:
    (tmp_path / "policy-coverage").mkdir()
    for part in (1, 3):
        (tmp_path / "policy-coverage" / f"cov.protect-agent-config.{part}").write_text("", encoding="utf-8")
    env = {"SPLIT": "protect-agent-config:3", "PATH": "/usr/bin:/bin"}
    run = subprocess.run(
        [BASH, "-c", COMBINE_STEP["run"]], cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )
    assert run.returncode == 1
    assert "part 2/3 left no coverage data" in run.stdout


@pytest.mark.parametrize("bad", ["failure", "cancelled", "skipped"])
def test_tests_fails_unless_every_tests_policy_cell_succeeds(bad: str) -> None:
    assert "tests-policy" in JOBS["tests"]["needs"]
    assert JOBS["tests"]["if"] == "always()"
    assert "tests" in JOBS["policies"]["needs"]
    assert GATE_STEP["env"]["POLICY"] == "${{ needs.tests-policy.result }}"

    def gate_exit(policy: str) -> int:
        env = {
            "SCOPE": "success",
            "FULL": "false",
            "HAS_MATRIX": "true",
            "SHARDS": "skipped",
            "TARGETED": "success",
            "POLICY": policy,
            "PATH": "/usr/bin:/bin",
        }
        return subprocess.run([BASH, "-c", GATE_STEP["run"]], env=env, capture_output=True, check=False).returncode

    assert gate_exit("success") == 0
    assert gate_exit(bad) == 1


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

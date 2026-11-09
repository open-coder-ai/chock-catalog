"""ci.yml: a heavy policy's tests-policy job runs as parts, each test in exactly one, its coverage still gated."""

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
from trees import ROOT

JOBS = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))["jobs"]
BASH = shutil.which("bash") or "bash"
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

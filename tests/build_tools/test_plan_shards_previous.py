"""plan_shards.py junit --previous: a shard that wrote no junit leaves its files' last recorded times in the plan."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import plan_shards
import pytest
from plan_shards import Times

ROOT = Path(__file__).resolve().parents[2]
JUNIT = """<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" tests="2">
<testcase classname="tests.a.test_x" name="test_one" time="1.500"/>
<testcase classname="tests.a.test_x" name="test_two" time="0.500"/></testsuite></testsuites>
"""


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(ROOT / "tools" / "plan_shards.py"), *args]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    for rel in ("tests/a/test_x.py", "tests/b/test_y.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("", encoding="utf-8")
    return tmp_path


def test_previous_times_fill_in_the_files_still_on_disk_that_no_junit_names(root: Path) -> None:
    found = {"tests/a/test_x.py": Times(2.0, 1.5, "new")}
    previous = {
        "tests/a/test_x.py": Times(9.0, 9.0, "old"),
        "tests/b/test_y.py": Times(4.0, 3.0, "kept"),
        "tests/c/test_gone.py": Times(7.0, 7.0, "deleted"),
    }
    assert plan_shards.merged(found, previous, root) == {
        "tests/a/test_x.py": Times(2.0, 1.5, "new"),
        "tests/b/test_y.py": Times(4.0, 3.0, "kept"),
    }


def test_junit_with_previous_keeps_the_times_of_a_shard_that_wrote_no_junit(root: Path) -> None:
    (root / "j.xml").write_text(JUNIT, encoding="utf-8")
    old = {"tests/b/test_y.py": {"seconds": 4.0, "longest": 3.0, "test": "kept"}}
    (root / "old.json").write_text(json.dumps(old), encoding="utf-8")
    assert run("junit", "t.json", "j.xml", "--previous", "old.json", cwd=root).returncode == 0
    assert plan_shards.load(root / "t.json") == {
        "tests/a/test_x.py": Times(2.0, 1.5, "test_one"),
        "tests/b/test_y.py": Times(4.0, 3.0, "kept"),
    }


def test_junit_without_previous_records_only_what_the_junit_files_name(root: Path) -> None:
    (root / "j.xml").write_text(JUNIT, encoding="utf-8")
    assert run("junit", "t.json", "j.xml", cwd=root).returncode == 0
    assert set(plan_shards.load(root / "t.json")) == {"tests/a/test_x.py"}

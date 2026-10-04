"""plan_shards.py report: the step summary of the slowest tests and files, and each shard planned against actual."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import plan_shards
import pytest

ROOT = Path(__file__).resolve().parents[2]
JUNIT = """<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" tests="1">
<testcase classname="tests.a.test_x" name="test_one" time="1.500"/></testsuite></testsuites>
"""


def write(path: Path, data: object) -> str:
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(ROOT / "tools" / "plan_shards.py"), *args]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    for rel in ("tests/a/test_x.py", "tests/b/test_y.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("", encoding="utf-8")
    return tmp_path


SUITE_XML = """<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" tests="2" time="{time}">
<testcase classname="tests.a.test_x" name="test_one[a|b]" time="{one}"/>
<testcase classname="tests.b.test_y" name="test_two`" time="{two}"/>
</testsuite></testsuites>
"""


def test_report_lists_the_slowest_tests_and_files_and_each_shard_planned_against_actual(root: Path) -> None:
    (root / "junit-1.xml").write_text(SUITE_XML.format(time="100.4", one="5.5", two="1.0"), encoding="utf-8")
    (root / "junit-2.xml").write_text(SUITE_XML.format(time="300.0", one="2.0", two="30.0"), encoding="utf-8")
    write(root / "plan.json", {"shards": 2, "assignment": {}, "split": [], "source": "durations", "planned": [90.0]})
    proc = run("report", "plan.json", "junit-1.xml", "junit-2.xml", cwd=root)
    assert proc.returncode == 0
    lines = proc.stdout.splitlines()
    assert lines[lines.index("## Slowest tests") + 5] == "| 5.5 | `tests.a.test_x::test_one[a\\|b]` |"
    assert "| 30.0 | `tests.b.test_y::test_two'` |" in lines
    assert "| 7.5 | 5.5 | `tests/a/test_x.py` |" in lines
    assert "| 31.0 | 30.0 | `tests/b/test_y.py` |" in lines
    assert "| 1 | 90 | 100 | 0.50 |" in lines
    assert "| 2 | - | 300 | 1.50 |" in lines


def test_report_numbers_a_junit_file_by_position_when_its_name_has_no_shard_and_survives_a_missing_suite(
    root: Path,
) -> None:
    (root / "a.xml").write_text("<testsuites></testsuites>", encoding="utf-8")
    (root / "b.xml").write_text("<testsuites><testsuite><testcase/></testsuite></testsuites>", encoding="utf-8")
    write(root / "plan.json", {"shards": 2, "assignment": {}, "split": [], "source": "none"})
    proc = run("report", "plan.json", "a.xml", "b.xml", cwd=root)
    assert proc.returncode == 0
    assert "| 1 | - | 0 | 0.00 |" in proc.stdout
    assert "| 2 | - | 0 | 0.00 |" in proc.stdout


def test_report_with_a_plan_that_is_not_one_is_an_error(root: Path) -> None:
    (root / "j.xml").write_text(JUNIT, encoding="utf-8")
    write(root / "plan.json", [1])
    with pytest.raises(ValueError, match="is not a shard plan"):
        plan_shards.main(["report", str(root / "plan.json"), str(root / "j.xml")])

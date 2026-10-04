"""plan_shards.py: junit times become a shard plan, and a file too slow to share a shard fails the run."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import plan_shards
import pytest

ROOT = Path(__file__).resolve().parents[2]
JUNIT = """<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" tests="3">
<testcase classname="tests.a.test_x" name="test_one[a&gt;b]" time="1.500"/>
<testcase classname="tests.a.test_x.TestCase" name="test_two" time="0.500"/>
<testcase classname="tests.b.test_y" name="test_three" time="2.000"><failure message="x"/></testcase>
<testcase classname="tests.conftest" name="test_hook" time="9.000"/>
</testsuite></testsuites>
"""


def write(path: Path, data: object) -> str:
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    for rel in ("tests/a/test_x.py", "tests/b/test_y.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("data", [[1], {"a": "slow"}, {"a": [1]}, "text"])
def test_a_file_that_is_not_name_to_seconds_is_no_times(tmp_path: Path, data: object) -> None:
    assert plan_shards.load(write(tmp_path / "t.json", data)) == {}


def test_a_missing_or_garbled_file_is_no_times(tmp_path: Path) -> None:
    assert plan_shards.load(tmp_path / "absent.json") == {}
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    assert plan_shards.load(tmp_path / "bad.json") == {}


def test_load_reads_seconds_as_floats(tmp_path: Path) -> None:
    assert plan_shards.load(write(tmp_path / "t.json", {"a.py": 3, "b.py": 1.5})) == {"a.py": 3.0, "b.py": 1.5}


@pytest.mark.parametrize(
    ("classname", "want"),
    [
        ("tests.a.test_x", "tests/a/test_x.py"),
        ("tests.a.test_x.TestCase", "tests/a/test_x.py"),
        ("tests.a.test_x.TestCase.Inner", "tests/a/test_x.py"),
        ("tests.conftest", None),
        ("tests.a.absent", None),
        ("", None),
    ],
)
def test_a_classname_names_the_longest_dotted_prefix_that_is_a_file(
    root: Path, classname: str, want: str | None
) -> None:
    assert plan_shards.test_file(classname, root) == want


def test_junit_files_sum_to_seconds_per_test_file_and_other_classes_are_left_out(root: Path, tmp_path: Path) -> None:
    one, two = tmp_path / "1.xml", tmp_path / "2.xml"
    one.write_text(JUNIT, encoding="utf-8")
    two.write_text(JUNIT.replace("9.000", "1"), encoding="utf-8")
    assert plan_shards.times_from_junit([str(one), str(two)], root) == {
        "tests/a/test_x.py": 4.0,
        "tests/b/test_y.py": 4.0,
    }


def test_a_testcase_without_a_time_counts_nothing(root: Path, tmp_path: Path) -> None:
    (tmp_path / "j.xml").write_text('<testcase classname="tests.a.test_x" name="t"/>', encoding="utf-8")
    assert plan_shards.times_from_junit([str(tmp_path / "j.xml")], root) == {"tests/a/test_x.py": 0.0}


def test_no_times_is_the_four_way_hash_split() -> None:
    assert plan_shards.plan({}) == {"shards": 4, "assignment": {}, "split": [], "source": "none"}


def test_the_shard_count_is_wall_time_over_the_target_between_the_floor_and_the_ceiling() -> None:
    def count(files: int, seconds: float) -> int:
        return plan_shards.plan({f"f{n}.py": seconds for n in range(files)}, target=100, workers=1)["shards"]

    assert count(1, 10) == 4
    assert count(5, 100) == 5
    assert count(5, 101) == 6
    assert count(1000, 100) == 16


def test_files_are_packed_longest_first_into_the_lightest_shard() -> None:
    times = {f"{n}.py": float(s) for n, s in enumerate((4, 4, 3, 3, 2, 2, 1, 1))}
    chosen = plan_shards.plan(times, target=100, workers=1)
    loads = [sum(times[f] for f, shard in chosen["assignment"].items() if shard == n) for n in range(1, 5)]
    assert (chosen["shards"], sorted(loads), chosen["split"]) == (4, [5.0, 5.0, 5.0, 5.0], [])
    assert set(chosen["assignment"]) == set(times)


def test_the_plan_is_deterministic_and_breaks_ties_by_name_then_shard() -> None:
    times = {"b.py": 1.0, "a.py": 1.0, "c.py": 1.0}
    chosen = plan_shards.plan(times, target=100, workers=1)
    assert chosen["assignment"] == {"a.py": 1, "b.py": 2, "c.py": 3}
    assert chosen == plan_shards.plan(dict(reversed(times.items())), target=100, workers=1)


def test_a_file_longer_than_a_shard_is_split_and_the_rest_are_packed_around_its_share() -> None:
    chosen = plan_shards.plan({"big.py": 1000.0, "a.py": 10.0, "b.py": 10.0}, target=100, workers=1)
    assert chosen["split"] == ["big.py"]
    assert "big.py" not in chosen["assignment"]
    assert sorted(chosen["assignment"]) == ["a.py", "b.py"]


def test_workers_turn_summed_seconds_into_wall_seconds() -> None:
    assert plan_shards.plan({"a.py": 800.0}, target=100, workers=8)["split"] == []
    assert plan_shards.plan({"a.py": 800.0}, target=100, workers=4)["split"] == ["a.py"]


def test_load_plan_returns_a_well_formed_plan(tmp_path: Path) -> None:
    chosen = {"shards": 2, "assignment": {"a.py": 1, "b.py": 2}, "split": [], "source": "durations"}
    assert plan_shards.load_plan(write(tmp_path / "p.json", chosen)) == chosen


@pytest.mark.parametrize(
    "bad",
    [
        {"shards": 2},
        {"assignment": {}},
        {"shards": 0, "assignment": {}},
        {"shards": "2", "assignment": {}},
        {"shards": 2, "assignment": []},
        {"shards": 2, "assignment": {"a.py": 3}},
        {"shards": 2, "assignment": {"a.py": 0}},
        {"shards": 2, "assignment": {"a.py": "1"}},
        [1],
    ],
)
def test_anything_but_a_well_formed_plan_is_an_error(tmp_path: Path, bad: object) -> None:
    with pytest.raises(ValueError, match="is not a shard plan"):
        plan_shards.load_plan(write(tmp_path / "p.json", bad))


def test_a_missing_or_garbled_plan_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="is not a shard plan"):
        plan_shards.load_plan(tmp_path / "absent.json")
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="is not a shard plan"):
        plan_shards.load_plan(tmp_path / "bad.json")


def test_over_lists_files_past_a_limit_slowest_first() -> None:
    times = {"a.py": 4 * 301.0, "b.py": 4 * 900.0, "c.py": 4 * 300.0}
    assert plan_shards.over(times, 300, workers=4) == {"b.py": 900.0, "a.py": 301.0}


def run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(ROOT / "tools" / "plan_shards.py"), *args]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


def test_junit_writes_the_times_of_the_test_files_under_the_working_directory(root: Path, tmp_path: Path) -> None:
    (tmp_path / "j.xml").write_text(JUNIT, encoding="utf-8")
    assert run("junit", "t.json", "j.xml", cwd=root).returncode == 0
    assert json.loads((root / "t.json").read_text(encoding="utf-8")) == {
        "tests/a/test_x.py": 2.0,
        "tests/b/test_y.py": 2.0,
    }


def test_plan_prints_json_and_says_so_when_there_are_no_times(tmp_path: Path) -> None:
    proc = run("plan", str(tmp_path / "absent.json"))
    assert json.loads(proc.stdout)["source"] == "none"
    assert "four-way hash split" in proc.stderr
    times = write(tmp_path / "t.json", {"a.py": 1.0})
    proc = run("plan", times)
    assert json.loads(proc.stdout)["source"] == "durations"
    assert proc.stderr == ""


def test_check_fails_naming_each_file_over_the_cap_and_warns_near_it(tmp_path: Path) -> None:
    times = write(tmp_path / "t.json", {"slow.py": 4 * 400.0, "near.py": 4 * 250.0, "ok.py": 4 * 10.0})
    proc = run("check", times)
    assert proc.returncode == 1
    assert "::error::slow.py takes about 400s" in proc.stdout
    assert "::warning::near.py takes about 250s" in proc.stdout
    assert "ok.py" not in proc.stdout
    assert "::warning::slow.py" not in proc.stdout


def test_check_with_warn_never_fails_and_a_clean_run_prints_nothing(tmp_path: Path) -> None:
    slow = write(tmp_path / "slow.json", {"slow.py": 4 * 400.0})
    proc = run("check", slow, "--warn")
    assert (proc.returncode, "::error::slow.py" in proc.stdout) == (0, True)
    assert run("check", write(tmp_path / "ok.json", {"ok.py": 4.0})).stdout == ""

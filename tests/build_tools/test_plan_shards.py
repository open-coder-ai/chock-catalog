"""plan_shards.py: junit times become a shard plan, and a single test too slow to balance fails the run."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import plan_shards
import pytest
from plan_shards import Times

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


def record(seconds: float, longest: float | None = None, test: str = "t") -> dict:
    return {"seconds": seconds, "longest": seconds if longest is None else longest, "test": test}


@pytest.mark.parametrize(
    "data",
    [
        [1],
        "text",
        {"a": "slow"},
        {"a": [1]},
        {"a.py": 3, "b.py": 1.5},
        {"a.py": {"seconds": 1, "longest": 1}},
        {"a.py": {"seconds": "1", "longest": 1, "test": "t"}},
        {"a.py": {"seconds": 1, "longest": True, "test": "t"}},
        {"a.py": {"seconds": 1, "longest": 1, "test": 5}},
        {"ok.py": {"seconds": 1, "longest": 1, "test": "t"}, "bad.py": 2},
    ],
)
def test_a_file_that_is_not_the_per_file_record_is_no_times(tmp_path: Path, data: object) -> None:
    assert plan_shards.load(write(tmp_path / "t.json", data)) == {}


def test_a_cache_saved_before_per_test_times_is_no_times_and_plans_the_hash_split(tmp_path: Path) -> None:
    old = write(tmp_path / "old.json", {"tests/a.py": 1500.0, "tests/b.py": 12.5})
    assert plan_shards.load(old) == {}
    proc = run("plan", old)
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {"shards": 4, "assignment": {}, "split": [], "source": "none"}
    assert "four-way hash split" in proc.stderr
    assert run("check", old).returncode == 0


def test_a_missing_or_garbled_file_is_no_times(tmp_path: Path) -> None:
    assert plan_shards.load(tmp_path / "absent.json") == {}
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    assert plan_shards.load(tmp_path / "bad.json") == {}


def test_load_reads_the_record_as_floats(tmp_path: Path) -> None:
    path = write(tmp_path / "t.json", {"a.py": record(3, 2, "slow[x]"), "b.py": record(1.5)})
    assert plan_shards.load(path) == {"a.py": Times(3.0, 2.0, "slow[x]"), "b.py": Times(1.5, 1.5, "t")}


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


def test_junit_files_sum_seconds_per_test_file_and_keep_the_longest_test_and_other_classes_are_left_out(
    root: Path, tmp_path: Path
) -> None:
    one, two = tmp_path / "1.xml", tmp_path / "2.xml"
    one.write_text(JUNIT, encoding="utf-8")
    two.write_text(
        JUNIT.replace("9.000", "1").replace('name="test_two" time="0.500"', 'name="test_two" time="3"'),
        encoding="utf-8",
    )
    assert plan_shards.times_from_junit([str(one), str(two)], root) == {
        "tests/a/test_x.py": Times(6.5, 3.0, "test_two"),
        "tests/b/test_y.py": Times(4.0, 2.0, "test_three"),
    }


def test_the_longest_test_is_named_as_written_not_as_escaped_in_the_xml(root: Path, tmp_path: Path) -> None:
    (tmp_path / "j.xml").write_text(JUNIT, encoding="utf-8")
    found = plan_shards.times_from_junit([str(tmp_path / "j.xml")], root)
    assert found["tests/a/test_x.py"] == Times(2.0, 1.5, "test_one[a>b]")


def test_a_testcase_without_a_time_counts_nothing(root: Path, tmp_path: Path) -> None:
    (tmp_path / "j.xml").write_text('<testcase classname="tests.a.test_x" name="t"/>', encoding="utf-8")
    assert plan_shards.times_from_junit([str(tmp_path / "j.xml")], root) == {"tests/a/test_x.py": Times(0.0, 0.0, "")}


def times(**seconds: float) -> dict[str, Times]:
    return {f"{name}.py": Times(value, value, "t") for name, value in seconds.items()}


def test_no_times_is_the_four_way_hash_split() -> None:
    assert plan_shards.plan({}) == {"shards": 4, "assignment": {}, "split": [], "source": "none"}


def test_the_shard_count_is_wall_time_over_the_target_between_the_floor_and_the_ceiling() -> None:
    def count(files: int, seconds: float) -> int:
        spread = {f"f{n}.py": Times(seconds, 0.0, "") for n in range(files)}
        return plan_shards.plan(spread, target=100, workers=1)["shards"]

    assert count(1, 10) == 4
    assert count(5, 100) == 5
    assert count(5, 101) == 6
    assert count(1000, 100) == 16


def test_files_are_packed_longest_first_into_the_lightest_shard() -> None:
    found = {f"{n}.py": Times(float(s), 0.0, "") for n, s in enumerate((4, 4, 3, 3, 2, 2, 1, 1))}
    chosen = plan_shards.plan(found, target=100, workers=1)
    loads = [sum(found[f].seconds for f, shard in chosen["assignment"].items() if shard == n) for n in range(1, 5)]
    assert (chosen["shards"], sorted(loads), chosen["split"]) == (4, [5.0, 5.0, 5.0, 5.0], [])
    assert set(chosen["assignment"]) == set(found)


def test_the_plan_is_deterministic_and_breaks_ties_by_name_then_shard() -> None:
    found = {name: Times(1.0, 0.0, "") for name in ("b.py", "a.py", "c.py")}
    chosen = plan_shards.plan(found, target=100, workers=1)
    assert chosen["assignment"] == {"a.py": 1, "b.py": 2, "c.py": 3}
    assert chosen == plan_shards.plan(dict(reversed(found.items())), target=100, workers=1)


def test_a_file_longer_than_a_shard_is_split_and_the_rest_are_packed_around_its_share() -> None:
    found = {"big.py": Times(1000.0, 0.0, ""), "a.py": Times(10.0, 0.0, ""), "b.py": Times(10.0, 0.0, "")}
    chosen = plan_shards.plan(found, target=100, workers=1)
    assert chosen["split"] == ["big.py"]
    assert "big.py" not in chosen["assignment"]
    assert sorted(chosen["assignment"]) == ["a.py", "b.py"]


def test_workers_turn_summed_seconds_into_wall_seconds() -> None:
    found = {"a.py": Times(800.0, 1.0, "")}
    assert plan_shards.plan(found, target=100, workers=8)["split"] == []
    assert plan_shards.plan(found, target=100, workers=4)["split"] == ["a.py"]


def test_a_file_is_never_faster_than_its_longest_test() -> None:
    assert plan_shards.wall(Times(400.0, 372.0, "t"), workers=4) == 372.0
    assert plan_shards.wall(Times(400.0, 20.0, "t"), workers=4) == 100.0
    one_test = plan_shards.plan({"a.py": Times(400.0, 372.0, "t"), "b.py": Times(8.0, 1.0, "t")}, target=270)
    assert one_test["split"] == ["a.py"]


def test_load_plan_returns_a_well_formed_plan(tmp_path: Path) -> None:
    chosen = {"shards": 2, "assignment": {"a.py": 1, "b.py": 2}, "split": [], "source": "durations"}
    path = write(tmp_path / "p.json", chosen)
    assert plan_shards.load_plan(path) == chosen


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


def test_over_lists_the_longest_test_of_files_past_a_limit_slowest_first() -> None:
    found = {"a.py": Times(9.0, 301.0, "one"), "b.py": Times(9.0, 900.0, "two"), "c.py": Times(9.0, 300.0, "three")}
    assert plan_shards.over(found, 300) == {"b.py": ("two", 900.0), "a.py": ("one", 301.0)}


def run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(ROOT / "tools" / "plan_shards.py"), *args]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


def test_junit_writes_the_times_of_the_test_files_under_the_working_directory(root: Path, tmp_path: Path) -> None:
    (tmp_path / "j.xml").write_text(JUNIT, encoding="utf-8")
    proc = run("junit", "t.json", "j.xml", cwd=root)
    assert proc.returncode == 0
    assert json.loads((root / "t.json").read_text(encoding="utf-8")) == {
        "tests/a/test_x.py": {"seconds": 2.0, "longest": 1.5, "test": "test_one[a>b]"},
        "tests/b/test_y.py": {"seconds": 2.0, "longest": 2.0, "test": "test_three"},
    }
    assert plan_shards.load(root / "t.json")["tests/a/test_x.py"] == Times(2.0, 1.5, "test_one[a>b]")


def test_plan_prints_json_and_says_so_when_there_are_no_times(tmp_path: Path) -> None:
    proc = run("plan", str(tmp_path / "absent.json"))
    assert json.loads(proc.stdout)["source"] == "none"
    assert "four-way hash split" in proc.stderr
    recorded = write(tmp_path / "t.json", {"a.py": record(1.0)})
    proc = run("plan", recorded)
    assert json.loads(proc.stdout)["source"] == "durations"
    assert proc.stderr == ""


def test_check_fails_naming_each_test_over_the_cap_and_warns_near_it(tmp_path: Path) -> None:
    found = {"slow.py": record(400, 400, "test_slow[a]"), "near.py": record(250, 250, "test_near"), "ok.py": record(10)}
    proc = run("check", write(tmp_path / "t.json", found))
    assert proc.returncode == 1
    assert "::error::slow.py::test_slow[a] takes 400s" in proc.stdout
    assert "::warning::near.py::test_near takes 250s" in proc.stdout
    assert "ok.py" not in proc.stdout
    assert "::warning::slow.py" not in proc.stdout


def test_a_file_of_many_short_tests_over_the_cap_in_total_passes(tmp_path: Path) -> None:
    many = write(tmp_path / "t.json", {"rows.py": record(4 * 500.0, 5.0, "test_row[1]")})
    proc = run("check", many)
    assert (proc.returncode, proc.stdout) == (0, "")


def test_one_test_of_301_seconds_fails_and_300_does_not(tmp_path: Path) -> None:
    assert run("check", write(tmp_path / "a.json", {"f.py": record(301, 301, "test_x")})).returncode == 1
    at_cap = run("check", write(tmp_path / "b.json", {"f.py": record(300, 300, "test_x")}))
    assert at_cap.returncode == 0
    assert "::warning::f.py::test_x takes 300s" in at_cap.stdout


def test_check_with_warn_never_fails(tmp_path: Path) -> None:
    slow = write(tmp_path / "slow.json", {"slow.py": record(400, 400, "test_slow")})
    proc = run("check", slow, "--warn")
    assert (proc.returncode, "::error::slow.py::test_slow" in proc.stdout) == (0, True)


def test_nothing_is_exempt_from_the_cap() -> None:
    assert not hasattr(plan_shards, "EXEMPT")

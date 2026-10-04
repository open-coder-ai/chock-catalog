"""durations.py: file times recorded from a run size the shards, balance them, and cap one file's share."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import durations
import pytest

ROOT = Path(__file__).resolve().parents[2]


def write(path: Path, data: object) -> str:
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("data", [[1], {"a": "slow"}, {"a": [1]}, "text"])
def test_a_file_that_is_not_name_to_seconds_is_no_data(tmp_path: Path, data: object) -> None:
    path = write(tmp_path / "d.json", data)
    assert durations.load(path) == {}


def test_a_missing_or_garbled_file_is_no_data(tmp_path: Path) -> None:
    assert durations.load(tmp_path / "absent.json") == {}
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    assert durations.load(tmp_path / "bad.json") == {}


def test_load_reads_seconds_as_floats(tmp_path: Path) -> None:
    path = write(tmp_path / "d.json", {"a.py": 3, "b.py": 1.5})
    assert durations.load(path) == {"a.py": 3.0, "b.py": 1.5}


def test_merge_adds_what_the_shards_report_and_sorts_by_name() -> None:
    assert durations.merge([{"b.py": 1.0}, {"a.py": 2.0, "b.py": 0.5}]) == {"a.py": 2.0, "b.py": 1.5}


def test_the_shard_count_is_the_wall_time_over_the_target_rounded_up() -> None:
    four_runs = {"a.py": 4 * 360.0 * 4}
    assert durations.shard_count(four_runs, target=360, workers=4) == 4
    assert durations.shard_count({"a.py": 4 * 360.0 * 4 + 1}, target=360, workers=4) == 5
    assert durations.shard_count({"a.py": 1.0}) == 1


def test_the_shard_count_has_a_default_with_no_data_and_a_ceiling() -> None:
    assert durations.shard_count({}) == durations.DEFAULT_SHARDS
    assert durations.shard_count({"a.py": 1e9}) == durations.MAX_SHARDS


def test_balance_puts_every_file_in_one_shard_and_evens_the_load() -> None:
    times = {"a.py": 4.0, "b.py": 4.0, "c.py": 3.0, "d.py": 3.0, "e.py": 2.0, "f.py": 2.0}
    placed = durations.balance(sorted(times), times, 2)
    assert set(placed) == set(times)
    assert [sum(times[f] for f in times if placed[f] == n) for n in (1, 2)] == [9.0, 9.0]


def test_balance_is_deterministic_and_breaks_ties_by_name_then_shard() -> None:
    times = {"b.py": 1.0, "a.py": 1.0, "c.py": 1.0}
    assert durations.balance(["c.py", "b.py", "a.py"], times, 2) == {"a.py": 1, "b.py": 2, "c.py": 1}
    assert durations.balance(["a.py", "b.py", "c.py"], times, 2) == durations.balance(list(reversed(times)), times, 2)


def test_a_file_with_no_recorded_time_costs_the_mean_and_is_still_placed() -> None:
    placed = durations.balance(["new.py", "a.py", "b.py"], {"a.py": 4.0, "b.py": 4.0, "gone.py": 99.0}, 3)
    assert sorted(placed.values()) == [1, 2, 3]


def test_with_no_times_at_all_every_file_still_gets_a_shard() -> None:
    assert sorted(durations.balance(["a.py", "b.py"], {}, 2).values()) == [1, 2]


def test_too_slow_lists_files_over_the_cap_slowest_first() -> None:
    times = {"a.py": 4 * 301.0, "b.py": 4 * 900.0, "c.py": 4 * 300.0}
    assert durations.too_slow(times, cap=300, workers=4) == {"b.py": 900.0, "a.py": 301.0}


def test_the_recorder_sums_every_phase_of_every_test_by_file_and_writes_when_the_session_ends(tmp_path: Path) -> None:
    out = tmp_path / "d.json"
    recorder = durations.Recorder(str(out))
    for nodeid, seconds in [("t/a.py::one[x]", 1.0), ("t/a.py::one[x]", 0.5), ("t/b.py::two", 2.0)]:
        recorder.pytest_runtest_logreport(SimpleNamespace(nodeid=nodeid, duration=seconds))
    recorder.pytest_sessionfinish()
    assert json.loads(out.read_text(encoding="utf-8")) == {"t/a.py": 1.5, "t/b.py": 2.0}


def test_the_option_is_registered_and_only_the_controller_records(tmp_path: Path) -> None:
    seen: dict[str, object] = {}
    durations.add_option(SimpleNamespace(addoption=lambda name, **kw: seen.update({name: kw})))
    assert seen["--durations-out"]["default"] is None
    registered: list[object] = []
    plugins = SimpleNamespace(register=registered.append)
    out = str(tmp_path / "d.json")
    durations.configure(SimpleNamespace(getoption=lambda _: out, pluginmanager=plugins))
    durations.configure(SimpleNamespace(getoption=lambda _: out, pluginmanager=plugins, workerinput={}))
    durations.configure(SimpleNamespace(getoption=lambda _: None, pluginmanager=plugins))
    assert len(registered) == 1


def run(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(ROOT / "tools" / "durations.py"), *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def test_shards_prints_the_numbers_one_to_n(tmp_path: Path) -> None:
    assert json.loads(run("shards", str(tmp_path / "absent.json")).stdout) == [1, 2, 3, 4]
    big = write(tmp_path / "d.json", {"a.py": 4 * 4 * 360.0 * 2})
    assert json.loads(run("shards", big, "--target", "360", "--workers", "4").stdout) == [1, 2, 3, 4, 5, 6, 7, 8]


def test_merge_writes_one_file_from_the_shards_files(tmp_path: Path) -> None:
    one, two = write(tmp_path / "1.json", {"a.py": 1}), write(tmp_path / "2.json", {"b.py": 2})
    assert run("merge", str(tmp_path / "all.json"), one, two).returncode == 0
    assert json.loads((tmp_path / "all.json").read_text(encoding="utf-8")) == {"a.py": 1.0, "b.py": 2.0}


def test_check_fails_naming_each_file_over_the_cap_and_passes_otherwise(tmp_path: Path) -> None:
    slow = write(tmp_path / "slow.json", {"tests/slow.py": 4 * 400.0, "tests/ok.py": 4 * 10.0})
    failed = run("check", slow, "--cap", "300", "--workers", "4")
    assert failed.returncode == 1
    assert "tests/slow.py: about 400s" in failed.stderr
    assert "tests/ok.py" not in failed.stderr
    assert run("check", slow, "--cap", "500").returncode == 0

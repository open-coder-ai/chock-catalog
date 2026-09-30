"""guard-memory-writes: the engine judges what a change adds from the gate's findings document."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import gatekit, scriptkit
from policies.test_guard_memory_writes import AWS, engine, fence, rows


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"MEMORY.md": "- old fact\n- old fact\n" + fence(30)})


def check(repo: Path, writes: dict[str, str], event: str = "commit") -> list[str]:
    return [f"{f['path']}:{f['line']}: {f['message']}" for f in rows(repo, writes, event)]


def test_a_long_block_already_at_head_does_not_block_an_unrelated_edit(repo: Path) -> None:
    text = "- old fact\n- old fact\n" + fence(30) + "- a new fact\n"
    assert engine(repo, {"MEMORY.md": text}) == 0
    assert engine(repo, {"MEMORY.md": text}, gatekit.COMMIT) == 0


def test_a_long_block_is_keyed_by_its_opener_and_body_so_a_grown_one_is_new(repo: Path) -> None:
    (row,) = [r for r in rows(repo, {"MEMORY.md": fence(30, "~~~")}) if r["key"].startswith("long-block")]
    assert row["key"].startswith("long-block|~~~|") and len(row["key"].split("|")[2]) == 16
    grown = "- old fact\n- old fact\n" + fence(30).replace("body 3\n", "body three\nbody 3.5\n")
    assert engine(repo, {"MEMORY.md": grown}) == 1


def test_a_second_long_block_with_the_same_opener_is_new(repo: Path) -> None:
    assert engine(repo, {"MEMORY.md": "- old fact\n- old fact\n" + fence(30) + fence(25)}) == 1


def test_a_long_block_with_another_opener_is_new(repo: Path) -> None:
    assert engine(repo, {"MEMORY.md": "- old fact\n- old fact\n" + fence(30) + fence(25, "~~~")}) == 1


def test_a_duplicate_already_at_head_is_not_reported(repo: Path) -> None:
    assert engine(repo, {"MEMORY.md": "- old fact\n- old fact\n" + fence(30) + "- fresh\n"}) == 0


def test_a_duplicate_is_keyed_by_the_normalized_line_and_survives_a_shift(repo: Path) -> None:
    (row,) = [r for r in rows(repo, {"MEMORY.md": "* old  fact\n1. old fact\n"}) if r["key"].startswith("duplicate")]
    assert row["key"] == "duplicate|old fact"
    assert engine(repo, {"MEMORY.md": "- new fact\n- old fact\n- old fact\n" + fence(30)}) == 0


def test_a_new_copy_of_a_committed_line_is_new(repo: Path) -> None:
    text = "- old fact\n- old fact\n- old fact\n" + fence(30)
    assert engine(repo, {"MEMORY.md": text}) == 1
    assert engine(repo, {"MEMORY.md": text}, gatekit.COMMIT) == 1


def test_a_new_secret_is_new_beside_an_old_one(tmp_path: Path) -> None:
    held = scriptkit.init_repo(tmp_path / "h", {"MEMORY.md": f"- key {AWS}\n"})
    assert engine(held, {"MEMORY.md": f"- key {AWS}\n- fact\n"}) == 0
    assert engine(held, {"MEMORY.md": f"- key {AWS}\n- key {AWS}x\n"}) == 1


def test_an_outside_file_is_judged_against_the_disk_not_head(repo: Path, tmp_path: Path) -> None:
    store = tmp_path / ".claude" / "projects" / "p" / "memory"
    store.mkdir(parents=True)
    target = store / "MEMORY.md"
    old = "- old fact\n- old fact\n" + fence(30)
    target.write_text(old, encoding="utf-8")
    path = target.as_posix()
    assert engine(repo, {path: old + "- fresh\n"}, gatekit.PRE_TOOL_USE) == 0
    assert engine(repo, {path: old + "- old fact\n"}, gatekit.PRE_TOOL_USE) == 1


def test_a_new_outside_file_is_judged_whole(repo: Path, tmp_path: Path) -> None:
    path = (tmp_path / ".claude" / "CLAUDE.md").as_posix()
    assert check(repo, {path: "- a\n- a\n"}, event="tool_use") == [f"{path}:2: duplicates line 1"]
    assert engine(repo, {path: "- a\n- a\n"}, gatekit.PRE_TOOL_USE) == 1
    assert engine(repo, {path: "- a\n- b\n"}, gatekit.PRE_TOOL_USE) == 0

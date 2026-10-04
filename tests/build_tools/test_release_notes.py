"""tools/release_notes.py prints each policy's changelog entries added since the last tag."""

from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

import pytest
import release_notes
import yaml

GIT = [
    "git",
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "tag.gpgsign=false",
]


def run(root: Path, *args: str) -> None:
    subprocess.run([*GIT, "-C", str(root), *args], check=True, capture_output=True)


def write(root: Path, tree: str, policy: str, changelog: list[dict] | None) -> None:
    folder = root / tree / policy
    folder.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"id": policy, "version": "1.0.0"}
    if changelog is not None:
        manifest["changelog"] = changelog
    (folder / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")


def entry(version: str, *changes: str) -> dict:
    return {"version": version, "date": "2026-10-01", "changes": list(changes)}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Tag v0.1.0 holds `alpha` at 0.0.1 and `quiet` with no changelog."""
    run(tmp_path, "init", "-q")
    write(tmp_path, "base", "alpha", [entry("0.0.1", "first")])
    write(tmp_path, "base", "quiet", None)
    run(tmp_path, "add", "-A")
    run(tmp_path, "commit", "-q", "-m", "baseline")
    run(tmp_path, "tag", "v0.1.0")
    return tmp_path


def test_only_entries_absent_from_the_tag_are_listed(repo: Path) -> None:
    write(repo, "base", "alpha", [entry("0.0.1", "first"), entry("0.0.2", "second", "third")])
    assert release_notes.render(repo, "0.2.0", "v0.1.0") == (
        "# Chock catalog v0.2.0\n\n## alpha\n\n- 0.0.2 (2026-10-01): second\n- 0.0.2 (2026-10-01): third\n"
    )


def test_a_policy_new_since_the_tag_lists_every_entry_across_trees(repo: Path) -> None:
    write(repo, "compliance", "beta", [entry("0.0.1", "born"), entry("0.0.2", "grew")])
    notes = release_notes.render(repo, "0.2.0", "v0.1.0")
    assert "## beta\n\n- 0.0.1 (2026-10-01): born\n- 0.0.2 (2026-10-01): grew\n" in notes
    assert "## alpha" not in notes


def test_a_policy_gaining_its_first_changelog_after_the_tag_is_listed(repo: Path) -> None:
    write(repo, "base", "quiet", [entry("0.0.1", "now documented")])
    assert "## quiet\n\n- 0.0.1 (2026-10-01): now documented\n" in release_notes.render(repo, "0.2.0", "v0.1.0")


def test_no_changes_since_the_tag_says_so(repo: Path) -> None:
    assert release_notes.render(repo, "0.2.0", "v0.1.0") == (
        "# Chock catalog v0.2.0\n\nNo policy changelog entries since v0.1.0.\n"
    )


def test_without_a_tag_every_entry_is_listed(repo: Path) -> None:
    notes = release_notes.render(repo, "0.1.0", None)
    assert notes == "# Chock catalog v0.1.0\n\n## alpha\n\n- 0.0.1 (2026-10-01): first\n"


@pytest.mark.parametrize("version", ["1.2", "v1.2.3", "1.2.3-rc1", "01.2.3", ""])
def test_a_version_that_is_not_semver_is_refused(repo: Path, version: str) -> None:
    with pytest.raises(ValueError, match=r"MAJOR\.MINOR\.PATCH"):
        release_notes.render(repo, version, None)


def test_an_unknown_tag_is_refused(repo: Path) -> None:
    with pytest.raises(ValueError, match=r"unknown tag 'v9\.9\.9'"):
        release_notes.render(repo, "0.2.0", "v9.9.9")


@pytest.mark.parametrize("tag", ["--output=x", "-x", "", "a b", "v1^{commit}"])
def test_a_tag_git_could_read_as_an_option_is_refused(repo: Path, tag: str) -> None:
    with pytest.raises(ValueError, match="unknown tag"):
        release_notes.render(repo, "0.2.0", tag)


def test_main_prints_the_notes(repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release_notes, "ROOT", repo)
    assert release_notes.main(["--version", "0.1.0"]) == 0
    assert capsys.readouterr().out.startswith("# Chock catalog v0.1.0\n")


def test_main_exits_2_on_a_bad_argument(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        release_notes.main(["--version", "x"])
    assert raised.value.code == 2
    assert "MAJOR.MINOR.PATCH" in capsys.readouterr().err


def test_the_script_entry_point_exits_with_main_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["release_notes.py", "--version", "x"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("release_notes", run_name="__main__")
    assert raised.value.code == 2

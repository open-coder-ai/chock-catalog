"""protect-ci-workflows: the other in-place writers, patches and variables (REVIEW-infra.md section 3)."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit

POLICY = "protect-ci-workflows"
GUARD = guardkit.load_guard(POLICY)
WORKFLOW = ".github/workflows/ci.yml"
PATCH_TEXT = f"--- a/{WORKFLOW}\n+++ b/{WORKFLOW}\n@@ -1 +1 @@\n-on: push\n+on: workflow_dispatch\n"
SOURCE_PATCH = "--- a/src/app.py\n+++ b/src/app.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"


def fill(command: str, patches: dict[str, str]) -> str:
    """The command with `{patch}` and `{other}` replaced by real patch files (braces in awk and shell stay)."""
    return command.replace("{patch}", patches["patch"]).replace("{other}", patches["other"])


@pytest.fixture
def patches(tmp_path: Path) -> dict[str, str]:
    workflow, other = tmp_path / "weaken-ci.patch", tmp_path / "fix-app.patch"
    workflow.write_text(PATCH_TEXT, encoding="utf-8")
    other.write_text(SOURCE_PATCH, encoding="utf-8")
    return {"patch": str(workflow), "other": str(other)}


@pytest.mark.parametrize(
    "command",
    [
        "yq -i '.a = 1' .github/workflows/ci.yml",
        "yq --inplace '.a = 1' .github/workflows/ci.yml",
        "yq e -i '.a = 1' .github/workflows/ci.yml",
        "yq -ie '.a = 1' .github/dependabot.yml",
        "curl -o .github/workflows/ci.yml https://example.com/ci.yml",
        "curl -fsSLo .github/workflows/ci.yml https://example.com/ci.yml",
        "curl --output .github/workflows/ci.yml https://example.com/ci.yml",
        "curl --output=.github/workflows/ci.yml https://example.com/ci.yml",
        "curl -o.github/workflows/ci.yml https://example.com/ci.yml",
        "wget -O .github/workflows/ci.yml https://example.com/ci.yml",
        "wget --output-document=.github/workflows/ci.yml https://example.com/ci.yml",
        "wget -qO .github/workflows/ci.yml https://example.com/ci.yml",
        "sponge .github/workflows/ci.yml",
        "sponge -a .github/actions/setup/action.yml",
        "git apply --directory=.github/workflows fix.patch",
        "git -C . apply {patch}",
        "git apply --apply {patch}",
        "patch .github/workflows/ci.yml fix.diff",
        "patch -i {patch}",
        "patch --input={patch} -p1",
    ],
)
def test_the_other_in_place_writers_are_refused(command: str, patches: dict[str, str]) -> None:
    assert GUARD.check(fill(command, patches)) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        "yq '.on' .github/workflows/ci.yml",
        "yq -i '.a = 1' config/app.yml",
        "curl -o /tmp/ci.yml https://example.com/ci.yml",
        "curl https://example.com/ci.yml",
        "curl -sS https://example.com/.github/workflows/ci.yml",
        "curl --silent --output /tmp/ci.yml https://example.com/ci.yml",
        "wget -O /tmp/x https://example.com/ci.yml",
        "sponge /tmp/out",
        "git apply {other}",
        "git apply --check {patch}",
        "git apply --stat {patch}",
        "git apply --numstat {patch}",
        "git apply --summary {patch}",
        "patch -p1 < {other}",
        "patch -i {other}",
        "patch -p1 < /nonexistent/never.patch",
        "git apply /nonexistent/never.patch",
        "patch src/app.py fix.diff",
    ],
)
def test_reads_and_unrelated_writers_of_those_commands_pass(command: str, patches: dict[str, str]) -> None:
    assert GUARD.check(fill(command, patches)) is None, command


def test_a_patch_is_read_from_the_directory_the_command_runs_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, patches: dict[str, str]
) -> None:
    Path(patches["patch"]).replace(tmp_path / "rel.patch")
    (tmp_path / "empty").mkdir()
    monkeypatch.chdir(tmp_path)
    assert GUARD.check("git apply rel.patch") is not None
    monkeypatch.chdir(tmp_path / "empty")
    assert GUARD.check("git apply rel.patch") is None


@pytest.mark.parametrize(
    "patch",
    [
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n",
        "rename to .github/workflows/ci.yml\n",
        "copy to .github/actions/x/action.yml\n",
        "--- a/.github/dependabot.yml\t2026-11-01 10:00:00\n",
        "+++ b/.github/workflows/ci.yml\r\n",
    ],
)
def test_every_header_of_a_patch_that_names_a_protected_path_counts(tmp_path: Path, patch: str) -> None:
    file = tmp_path / "x.patch"
    file.write_text("noise\n" + patch, encoding="utf-8")
    assert GUARD.check(f"git apply {file}") is not None


def test_a_patch_too_large_to_read_whole_is_read_up_to_a_cap(tmp_path: Path) -> None:
    file = tmp_path / "big.patch"
    file.write_text("x\n" * 600_000 + PATCH_TEXT, encoding="utf-8")
    assert GUARD.check(f"git apply {file}") is None  # past the cap: not judged, and the manifest says so


def test_a_patch_that_is_a_directory_or_not_text_is_not_judged(tmp_path: Path) -> None:
    binary = tmp_path / "b.patch"
    binary.write_bytes(b"\xff\xfe\x00\n" + PATCH_TEXT.encode("utf-8"))
    assert GUARD.check(f"git apply {tmp_path}") is None
    assert GUARD.check(f"git apply {binary}") is not None  # undecodable bytes are replaced, the header still reads


@pytest.mark.parametrize(
    "command",
    [
        'f=.github/workflows/ci.yml; rm "$f"',
        "f=.github/workflows/ci.yml && rm ${f}",
        'dir=.github; rm -rf "$dir/workflows"',
        'f=.github/workflows/ci.yml; echo x > "$f"',
        'f=.github/workflows/ci.yml\nrm "$f"',
        'a=.github; b=$a/workflows; rm -rf "$b"',
        'f=.github/workflows/ci.yml; g=$f; mv /tmp/x "$g"',
    ],
)
def test_a_path_held_in_a_variable_is_read_from_the_line(command: str) -> None:
    assert GUARD.check(command) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        'f=notes.md; rm "$f"',
        'rm "$f"',
        'f=.github/workflows/ci.yml; cat "$f"',
        'f=.github/workflows/ci.yml; f=notes.md; rm "$f"',
        'rm "${undefined}"',
        "rm '$f'",
    ],
)
def test_a_variable_that_does_not_hold_a_protected_path_passes(command: str) -> None:
    assert GUARD.check(command) is None, command

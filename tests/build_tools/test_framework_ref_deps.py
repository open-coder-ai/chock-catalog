"""tools/framework_ref.py: the framework's git pins are installed from it, by commit, and checked after."""

from __future__ import annotations

from pathlib import Path

import framework_ref
import pytest

SHA = "5c9350738729a2cf1c40f5851628384751cae484"


AGENTSEAM = "git+https://github.com/open-coder-ai/agentseam"


def _framework(tmp_path: Path, *deps: str) -> str:
    lines = ", ".join(f'"{d}"' for d in deps)
    (tmp_path / "pyproject.toml").write_text(f'[project]\nname = "chock"\ndependencies = [{lines}]\n', encoding="utf-8")
    return str(tmp_path)


def test_direct_deps_prints_each_commit_pin_without_spaces(tmp_path: Path, capsys) -> None:
    """Run 39188425493: chock pinned an agentseam commit and the catalog installed PyPI's 0.3.5 instead."""
    path = _framework(
        tmp_path,
        f"agentseam @ {AGENTSEAM}@{SHA}",
        "pyyaml>=6.0",
        f"other[cli] @ git+https://github.com/open-coder-ai/other.git@{SHA} ; python_version >= '3.9'",
    )
    assert framework_ref.main(["direct-deps", path]) == 0
    assert capsys.readouterr().out == (
        f"agentseam@{AGENTSEAM}@{SHA}\nother@git+https://github.com/open-coder-ai/other.git@{SHA}\n"
    )


def test_direct_deps_prints_nothing_for_version_pins(tmp_path: Path, capsys) -> None:
    path = _framework(tmp_path, "agentseam==0.3.5", "jsonschema>=4.18,<5")
    assert framework_ref.main(["direct-deps", path]) == 0
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "url",
    [
        f"{AGENTSEAM}@main",
        f"{AGENTSEAM}@v0.3.5",
        f"{AGENTSEAM}@{SHA[:12]}",
        f"{AGENTSEAM}@{SHA.upper()}",
        f"{AGENTSEAM}@{SHA}0",
        f"{AGENTSEAM}",
        f"git+https://github.com/someone/agentseam@{SHA}",
        f"git+https://gitlab.com/open-coder-ai/agentseam@{SHA}",
        f"git+http://github.com/open-coder-ai/agentseam@{SHA}",
        f"https://github.com/open-coder-ai/agentseam/archive/{SHA}.tar.gz",
        f"file:///src/agentseam-{SHA}",
    ],
)
def test_direct_deps_refuses_anything_but_an_org_commit(tmp_path: Path, capsys, url: str) -> None:
    path = _framework(tmp_path, f"agentseam @ {url}")
    assert framework_ref.main(["direct-deps", path]) == framework_ref.REFUSED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"::error::{path}/pyproject.toml pins agentseam @ {url}" in captured.err


def test_direct_deps_refuses_a_checkout_without_a_project_table(tmp_path: Path, capsys) -> None:
    assert framework_ref.main(["direct-deps", str(tmp_path)]) == framework_ref.REFUSED
    assert "no [project] table" in capsys.readouterr().err


def _deps(monkeypatch: pytest.MonkeyPatch, path: str, installed: dict[str, tuple[dict, str]]) -> int:
    monkeypatch.setattr(framework_ref, "_installed", installed.get)
    return framework_ref.main(["deps", path])


@pytest.mark.parametrize(
    "repo", ["https://github.com/open-coder-ai/agentseam", "https://github.com/open-coder-ai/agentseam.git"]
)
def test_deps_accepts_the_pinned_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, repo: str) -> None:
    path = _framework(tmp_path, f"agentseam @ {AGENTSEAM}@{SHA}", "pyyaml>=6.0")
    origin = {"url": repo, "vcs_info": {"vcs": "git", "commit_id": SHA}}
    assert _deps(monkeypatch, path, {"agentseam": (origin, "0.3.5")}) == 0
    assert "is installed at its commit" in capsys.readouterr().out


def test_deps_refuses_the_index_release_of_the_same_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """Run 39188425493: chock pinned an agentseam commit, PyPI's 0.3.5 was installed, and pip check passed."""
    path = _framework(tmp_path, f"agentseam @ {AGENTSEAM}@{SHA}")
    assert _deps(monkeypatch, path, {"agentseam": ({}, "0.3.5")}) == framework_ref.REFUSED
    err = capsys.readouterr().err
    assert f"pins agentseam @ {AGENTSEAM}@{SHA}, but the installed agentseam is 0.3.5 from a package index" in err


@pytest.mark.parametrize(
    "origin",
    [
        {"url": "https://github.com/open-coder-ai/agentseam", "vcs_info": {"vcs": "git", "commit_id": "1" * 40}},
        {"url": "https://github.com/someone/agentseam", "vcs_info": {"vcs": "git", "commit_id": SHA}},
        {"url": f"https://github.com/open-coder-ai/agentseam/archive/{SHA}.tar.gz", "archive_info": {}},
        {"url": f"file:///src/agentseam-{SHA}", "dir_info": {}},
    ],
)
def test_deps_refuses_another_commit_or_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, origin: dict) -> None:
    path = _framework(tmp_path, f"agentseam @ {AGENTSEAM}@{SHA}")
    assert _deps(monkeypatch, path, {"agentseam": (origin, "0.3.5")}) == framework_ref.REFUSED


def test_deps_refuses_a_pinned_dependency_that_is_not_installed(tmp_path: Path, monkeypatch, capsys) -> None:
    path = _framework(tmp_path, f"agentseam @ {AGENTSEAM}@{SHA}")
    assert _deps(monkeypatch, path, {}) == framework_ref.REFUSED
    assert "agentseam is not installed" in capsys.readouterr().err


def test_deps_leaves_version_pins_to_pip_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _framework(tmp_path, "agentseam==0.3.5", "jsonschema>=4.18,<5")
    assert _deps(monkeypatch, path, {}) == 0


def test_deps_refuses_a_checkout_without_a_project_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    assert _deps(monkeypatch, str(tmp_path), {}) == framework_ref.REFUSED
    assert "no [project] table" in capsys.readouterr().err

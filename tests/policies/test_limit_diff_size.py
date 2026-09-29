"""limit-diff-size: the commit-time script, driven against temporary git repositories."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from policies import scriptkit

NAME = "limit-diff-size-pre-commit.py"
mod = scriptkit.load("limit-diff-size", NAME)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("CHOCK_DIFF_LIMIT", "CHOCK_ALLOW_LARGE_DIFF", "CHOCK_AGENT_COMMIT"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = scriptkit.init_repo(tmp_path / "r", {"README.txt": "base\n"})
    monkeypatch.chdir(path)
    return path


def stage(repo: Path, files: dict[str, str | bytes]) -> None:
    scriptkit.write(repo, files)
    scriptkit.git(repo, "add", "-A")


def lines(n: int) -> str:
    return "".join(f"line {i}\n" for i in range(n))


def verdict(capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = mod.main()
    return code, capsys.readouterr().err


def test_a_small_change_is_allowed(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    stage(repo, {"a.py": lines(500)})
    assert verdict(capsys) == (0, "")


def test_a_change_over_the_limit_is_refused_with_the_five_largest_files(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stage(repo, {f"f{i}.py": lines(100 + i * 10) for i in range(7)})
    code, err = verdict(capsys)
    assert code == 3
    assert "staged diff is 910 lines" in err
    assert "limit is 500" in err
    listed = [ln for ln in err.splitlines() if ln.startswith("  ") and ".py" in ln]
    assert [ln.split()[1] for ln in listed] == ["f6.py", "f5.py", "f4.py", "f3.py", "f2.py"]
    assert "git add -p" in err
    assert "CHOCK_ALLOW=limit-diff-size" in err
    assert "CHOCK_ALLOW_LARGE_DIFF=1 still works" in err
    assert "ask the person" in err


def test_removed_lines_count_as_much_as_added_ones(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    stage(repo, {"big.txt": lines(600)})
    scriptkit.git(repo, "commit", "-q", "-m", "big")
    stage(repo, {"big.txt": lines(200)})
    assert verdict(capsys)[0] == 0  # 400 removed
    stage(repo, {"big.txt": "x\n"})
    code, err = verdict(capsys)  # 600 removed + 1 added
    assert code == 3
    assert "601 lines" in err


@pytest.mark.parametrize(
    "path",
    [
        "package-lock.json",
        "web/yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "Cargo.lock",
        "go.sum",
        "Gemfile.lock",
        "composer.lock",
        "custom.lock",
        "vendor/lib/a.go",
        "node_modules/x/index.js",
        "packages/a/node_modules/x/index.js",
        "dist/bundle.js",
        "web/build/out.js",
        "app.min.js",
        "site.min.css",
        "tests/__snapshots__/a.snap",
        ".chock/compiled/x/gate.json",
    ],
)
def test_lockfiles_generated_and_vendored_paths_are_not_counted(
    repo: Path, capsys: pytest.CaptureFixture[str], path: str
) -> None:
    stage(repo, {path: lines(2000), "src/real.py": lines(10)})
    assert verdict(capsys) == (0, "")


def test_a_file_that_only_looks_generated_is_counted(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    stage(repo, {"src/build.py": lines(300), "src/dist_tools.py": lines(300), "lockfile.txt": lines(300)})
    code, err = verdict(capsys)
    assert code == 3
    assert "900 lines" in err


def test_binary_files_are_skipped(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    stage(repo, {"logo.png": b"\x00\x01\x02" * 5000, "a.py": lines(5)})
    assert verdict(capsys) == (0, "")


def test_a_pure_rename_costs_nothing_and_a_rename_with_edits_costs_the_edits(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stage(repo, {"old.txt": lines(800)})
    scriptkit.git(repo, "commit", "-q", "-m", "big")
    scriptkit.git(repo, "mv", "old.txt", "new.txt")
    assert verdict(capsys) == (0, "")
    stage(repo, {"new.txt": lines(800).replace("line 1\n", "changed\n")})
    assert verdict(capsys) == (0, "")  # one line replaced: 2 counted
    (repo / "dist").mkdir()
    scriptkit.git(repo, "mv", "new.txt", "dist/new.txt")
    assert verdict(capsys) == (0, "")


def test_the_limit_comes_from_chock_diff_limit(
    repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    stage(repo, {"a.py": lines(20)})
    monkeypatch.setenv("CHOCK_DIFF_LIMIT", "10")
    code, err = verdict(capsys)
    assert code == 3
    assert "limit is 10" in err
    monkeypatch.setenv("CHOCK_DIFF_LIMIT", "20")
    assert verdict(capsys) == (0, "")


@pytest.mark.parametrize("bad", ["abc", "0", "-5", "", "1.5"])
def test_an_unusable_limit_falls_back_to_500(
    repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    monkeypatch.setenv("CHOCK_DIFF_LIMIT", bad)
    stage(repo, {"a.py": lines(501)})
    code, err = verdict(capsys)
    assert code == 3
    assert "limit is 500" in err


def test_a_person_can_override_for_one_commit(
    repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    stage(repo, {"a.py": lines(900)})
    monkeypatch.setenv("CHOCK_ALLOW_LARGE_DIFF", "1")
    code, err = verdict(capsys)
    assert code == 0
    assert "allowed by CHOCK_ALLOW_LARGE_DIFF" in err


def test_a_falsy_override_does_not_override(
    repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    stage(repo, {"a.py": lines(900)})
    monkeypatch.setenv("CHOCK_ALLOW_LARGE_DIFF", "0")
    assert verdict(capsys)[0] == 3


def test_an_agents_commit_cannot_use_the_override(
    repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    stage(repo, {"a.py": lines(900)})
    monkeypatch.setenv("CHOCK_ALLOW_LARGE_DIFF", "1")
    monkeypatch.setenv("CHOCK_AGENT_COMMIT", "1")
    code, err = verdict(capsys)
    assert code == 3
    assert "ignored, this is an agent's commit" in err
    assert "staged diff is 900 lines" in err


def test_outside_a_repository_the_script_refuses_rather_than_allows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    code, err = verdict(capsys)
    assert code == 1
    assert "refusing rather than allowing" in err


def test_the_script_runs_as_a_process_and_speaks_through_its_exit_code(tmp_path: Path) -> None:
    repo = scriptkit.init_repo(tmp_path / "p", {"README.txt": "base\n"})
    stage(repo, {"a.py": lines(600)})
    env = {k: v for k, v in os.environ.items() if not k.startswith("CHOCK_")}
    code, err = scriptkit.run_script("limit-diff-size", NAME, repo, env=env)
    assert code == 3
    assert "600 lines" in err
    code, _ = scriptkit.run_script("limit-diff-size", NAME, repo, env={**env, "CHOCK_DIFF_LIMIT": "700"})
    assert code == 0

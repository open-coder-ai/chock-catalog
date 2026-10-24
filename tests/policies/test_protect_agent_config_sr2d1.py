"""protect-agent-config 0.7.4: the hooks folder core.hooksPath names, bounded brace expansion, bounded path depth."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit

GUARD = guardkit.load_guard("protect-agent-config")
PATHSET = guardkit.load_guard("protect-agent-config", "pathset")
PATHTEXT = guardkit.load_guard("protect-agent-config", "pathtext")
PATHLINK = guardkit.load_guard("protect-agent-config", "pathlink")
PATHWRAP = guardkit.load_guard("protect-agent-config", "pathwrap")
BLOCK = PATHSET.BLOCK


def forget_configs() -> None:
    """The guard reads each repository's git config once per process; a test that rewrites it starts over."""
    PATHSET.in_hooks_folder.__globals__["_folders"].cache_clear()


def repo(tmp_path: Path, config: str, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repository folder whose .git/config holds `config`, with no global or system git config to read."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(config)
    forget_configs()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return tmp_path


@pytest.mark.parametrize(
    ("config", "path"),
    [
        ("[core]\n\thooksPath = .githooks\n", ".githooks/pre-commit"),
        ("[core]\n\thooksPath = .githooks\n", ".githooks/pre-commit.d/50-chock-policy-001"),
        ("[core]\n\thooksPath = .githooks\n", ".githooks"),
        ("[core]\n\thooksPath = .githooks\n", "./.githooks//pre-push"),
        ("[core]\n\thooksPath = .githooks\n", ".GITHOOKS/Pre-Commit"),
        ("[core]\n\thooksPath = .githooks/\n", ".githooks/commit-msg"),
        ("[core]\n\thookspath=.husky/_\n", ".husky/_/pre-commit"),
        ('[core]\n\thooksPath = "tools/hooks"\n', "tools/hooks/pre-commit"),
        ("[core]\n\tbare = false\n\tHOOKSPATH = tools/hooks # ours\n", "tools/hooks/pre-commit"),
        ("[core]\n\thooksPath = /opt/team-hooks\n", "/opt/team-hooks/pre-commit"),
    ],
)
def test_the_configured_hooks_folder_is_protected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config: str, path: str
) -> None:
    repo(tmp_path, config, monkeypatch)
    assert PATHSET.verdict(path, str(tmp_path)) == BLOCK
    assert PATHSET.verdict(path) == BLOCK


@pytest.mark.parametrize(
    ("config", "path"),
    [
        ("", ".githooks/pre-commit"),
        ("[core]\n\tbare = false\n", ".githooks/pre-commit"),
        ("[core]\n\thooksPath = .githooks\n", "src/app.py"),
        ("[core]\n\thooksPath = .githooks\n", ".githooks-old/pre-commit"),
        ("[core]\n\thooksPath = .githooks\n", "githooks/pre-commit"),
        ('[core "x"]\n\thooksPath = .githooks\n', ".githooks/pre-commit"),
        ("[coreish]\n\thooksPath = .githooks\n", ".githooks/pre-commit"),
        ("[core]\n\t# hooksPath = .githooks\n", ".githooks/pre-commit"),
        ("[core]\n\thooksPath =\n", "src/app.py"),
        ("[core]\n\thooksPath = .\n", "src/app.py"),
        ("[core]\n\thooksPath = /\n", "src/app.py"),
    ],
)
def test_nothing_else_is_protected_by_the_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config: str, path: str
) -> None:
    repo(tmp_path, config, monkeypatch)
    assert PATHSET.verdict(path, str(tmp_path)) == ""


def test_a_global_setting_counts_and_an_unreadable_config_does_not_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo(tmp_path, "", monkeypatch)
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / ".gitconfig").write_text("[core]\n\thooksPath = .globalhooks\n")
    assert PATHSET.verdict(".globalhooks/pre-commit", str(tmp_path)) == BLOCK
    forget_configs()
    (tmp_path / "home" / ".gitconfig").unlink()
    (tmp_path / "home" / ".gitconfig").mkdir()  # a folder where a file is read: no setting, no fault
    assert PATHSET.verdict(".globalhooks/pre-commit", str(tmp_path)) == ""
    forget_configs()
    (tmp_path / ".git" / "config").write_bytes(b"[core]\n\thooksPath = \xff\xfe\n")
    assert PATHSET.verdict(".globalhooks/pre-commit", str(tmp_path)) == ""


@pytest.mark.parametrize(
    "raw",
    [
        "echo 'exit 0' > .githooks/pre-commit",
        "rm .githooks/pre-commit.d/50-chock-policy-001",
        "rm -rf .githooks",
        "chmod -x .githooks/pre-commit",
        "cd .githooks && rm pre-commit",
        "mv .githooks/pre-push /tmp/x",
    ],
)
def test_the_shell_guard_refuses_writes_to_the_configured_hooks_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    repo(tmp_path, "[core]\n\thooksPath = .githooks\n", monkeypatch)
    assert GUARD.check(raw) is not None, raw


@pytest.mark.parametrize("raw", ["cat .githooks/pre-commit", "ls .githooks"])
def test_the_shell_guard_allows_reads_of_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    repo(tmp_path, "[core]\n\thooksPath = .githooks\n", monkeypatch)
    assert GUARD.check(raw) is None, raw


def test_brace_expansion_is_bounded_in_work_not_only_in_output(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    real = PATHTEXT.braces

    def counting(word: str, *rest: object) -> list[str]:
        calls.append(word)
        return real(word, *rest)

    monkeypatch.setattr(PATHTEXT, "braces", counting)
    found = PATHTEXT.braces("{a,b}" * 14 + "/x")
    assert len(calls) < 5000
    assert PATHTEXT.SUBST in found
    assert len(found) <= 129


def test_a_word_of_wide_brace_ranges_does_not_exhaust_the_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo(tmp_path, "", monkeypatch)
    (tmp_path / ".claude").mkdir()
    raw = "false && : > {1..999}{1..999}{1..999}{1..999}; cd .claude && printf x > settings.local.json"
    assert GUARD.check(raw) is not None


def test_a_path_of_a_thousand_segments_is_refused_not_a_fault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo(tmp_path, "", monkeypatch)
    (tmp_path / ".claude").mkdir()
    deep = "/".join("a" * 1500)
    assert PATHLINK.follow(str(tmp_path), deep) is None
    assert GUARD.check(f"false && : > {deep}; cd .claude && printf x > settings.local.json") is not None


def test_an_ordinary_deep_path_is_still_followed(tmp_path: Path) -> None:
    assert PATHLINK.follow(str(tmp_path), "/".join("a" * 100)) == {str(tmp_path / "/".join("a" * 100))}


@pytest.mark.parametrize(
    ("raw", "scripts"),
    [
        ("env --split-string='cat a b'", ["cat a b"]),
        ("env -S'cat a b'", ["cat a b"]),
        ("env -S 'cat a' b", ["cat a b"]),
        ("env -u HOME -S'ls'", ["ls"]),
        ("env FOO=1 ls", []),
    ],
)
def test_the_env_split_string_is_still_collected_for_the_loose_check(raw: str, scripts: list[str]) -> None:
    assert PATHWRAP.env_scripts(raw) == scripts

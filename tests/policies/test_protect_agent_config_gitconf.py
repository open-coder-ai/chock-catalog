"""protect-agent-config: `git config` writes of keys that run code, `--file` at the repository config, git environment routes."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guard_cases_gitconf as cases
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
conf = guardkit.load_guard(POLICY, "pathconf")


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in (".git", ".git/hooks", ".claude", ".cursor", ".chock", "src"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", cases.GIT_CONFIG_REFUSED)
def test_a_git_config_that_can_run_code_or_rewrite_the_repository_config_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", cases.GIT_CONFIG_ALLOWED)
def test_a_git_config_read_or_an_ordinary_key_is_allowed(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize("key", cases.CODE_KEYS)
def test_every_code_running_key_is_known_in_any_letter_case(key: str) -> None:
    assert conf.code_key(key)
    assert conf.code_key(key.upper())


@pytest.mark.parametrize(
    "key", ["user.name", "user.email", "core.autocrlf", "pull.rebase", "remote.origin.url", "core"]
)
def test_an_ordinary_key_does_not_run_code(key: str) -> None:
    assert not conf.code_key(key)


def test_the_environment_route_reads_every_key_it_sets() -> None:
    assert conf.route({"GIT_CONFIG_KEY_3": "alias.x"})
    assert conf.route({"GIT_CONFIG_PARAMETERS": "'user.name=a' 'core.pager=b'"})
    assert conf.route({"GIT_CONFIG_PARAMETERS": "'unterminated"})
    assert not conf.route({"GIT_CONFIG_KEY_0": "user.name", "GIT_CONFIG_KEY_X": "alias.x", "HOME": "/srv"})
    assert not conf.route({})

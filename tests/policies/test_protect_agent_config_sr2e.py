"""protect-agent-config 0.7.6: `mkdir` at or under a folder whose bare existence a gate reads is refused, in every spelling the guard reads."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit

GUARD = guardkit.load_guard("protect-agent-config")
SET = guardkit.load_guard("protect-agent-config", "pathset")

REFUSED = [
    "mkdir .chock/compiled/some-policy",
    "mkdir -p .chock/compiled/some-policy",
    "mkdir -p .chock/compiled/some-policy/stop",
    "mkdir -p deep/er/.chock/compiled/some-policy",
    "md .chock/compiled/some-policy",
    "mkdir -m 755 .chock/compiled/some-policy",
    "mkdir -p .chock/compiled/{a,b}",
    "mkdir -p build .chock/compiled/some-policy",
    'mkdir -p ".chock/compiled/some-policy"',
    "mkdir -p .CHOCK/COMPILED/some-policy",
    "mkdir -p .chock/compiled/some-policy/",
    "mkdir .chock\\compiled\\some-policy",
    "cd .chock && mkdir -p compiled/some-policy",
    "D=.chock; mkdir -p $D/compiled/some-policy",
    "bash -c 'mkdir -p .chock/compiled/some-policy'",
    "mkdir -p build && mkdir -p .chock/compiled/some-policy",
]
OPEN = [
    "mkdir -p build/out",
    "mkdir -p build/out && cp dist/*.whl build/out/",
    "mkdir -p .claude/commands",
    "mkdir .cursor",
    "mkdir .opencode",
    "mkdir -p .agents/policies/some-policy",
    "mkdir .chock",
    "mkdir plug2",
    "mkdir -p src/chock/compiled-notes",
    "mkdir -p docs/compiled",
    "mkdir -p tests/chock_compiled",
    "ls .chock/compiled",
]


@pytest.fixture(autouse=True)
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".chock").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


@pytest.mark.parametrize("raw", REFUSED)
def test_making_a_folder_under_the_compiled_tree_is_refused(raw: str) -> None:
    assert GUARD.check(raw) == GUARD.REASON, raw


@pytest.mark.parametrize("raw", OPEN)
def test_making_any_other_folder_stays_open(raw: str) -> None:
    assert GUARD.check(raw) is None, raw


def test_the_presence_folders_are_taken_from_the_protected_paths() -> None:
    assert SET.PRESENCE
    assert all(entry in SET.PROTECTED for entry in SET.PRESENCE)

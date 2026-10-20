"""protect-agent-config 0.7.0: chock.lock, the hashes `chock check` verifies against, is a protected file (CAT-6)."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import gatekit, guardkit, scriptkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)

REFUSED = [
    "rm chock.lock",
    "rm -f ./chock.lock",
    "rm CHOCK.LOCK",
    "del chock.lock",
    "echo '{}' > chock.lock",
    "echo x >> chock.lock",
    "echo x | tee chock.lock",
    "sed -i s/sha256/x/ chock.lock",
    "truncate -s 0 chock.lock",
    "mv chock.lock chock.lock.old",
    "cp /tmp/forged.lock chock.lock",
    "git checkout -- chock.lock",
    "git restore chock.lock",
    "bash -c 'rm chock.lock'",
    "cd src && rm ../chock.lock",
    "rm sub/chock.lock",
    "rm chock.lock:1",
    "echo x > $PWD/chock.lock",
    "rm -rf .",
]

ALLOWED = [
    "cat chock.lock",
    "git diff chock.lock",
    "git add chock.lock",
    "git commit -m x chock.lock",
    "grep sha256 chock.lock",
    "chock check",
    "chock sync --repo .",
    "ls chock.lock",
    "echo x > docs/chock.lock.md",
    "rm chock.lock.bak",
    "rm mychock.lock",
    "echo x > src/chock.locker",
    "git commit -m 'update chock.lock'",
]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = scriptkit.init_repo(tmp_path / "r", {"chock.lock": "lockfile_version: '1'\n", "src/app.py": "x = 1\n"})
    (root / "sub").mkdir()
    (root / "sub/chock.lock").write_text("x\n", encoding="utf-8")
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


@pytest.mark.parametrize("raw", REFUSED)
def test_a_shell_write_to_the_lockfile_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", ALLOWED)
def test_reading_the_lockfile_and_a_file_merely_named_like_it_stay_open(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize(
    "path", ["chock.lock", "./chock.lock", "CHOCK.LOCK", "sub/chock.lock", "src/../chock.lock", "chock.lock\\"]
)
def test_the_tool_gate_refuses_a_write_to_the_lockfile(_repo_root: Path, path: str) -> None:
    code, err = gatekit.judge(POLICY, _repo_root, gatekit.PRE_TOOL_USE, {path: "x\n"}, {path: "x\n"})
    assert code == 1
    assert "forbidden path" in err


def test_the_tool_gate_refuses_the_lockfile_by_a_windows_absolute_path(_repo_root: Path) -> None:
    path = "C:\\work\\repo\\chock.lock"
    assert gatekit.judge(POLICY, _repo_root, gatekit.PRE_TOOL_USE, {path: "x\n"}, {path: "x\n"})[0] == 1


@pytest.mark.parametrize("path", ["docs/chock.lock.md", "chock.lock.bak", "src/chock.locker", "chock.lockfile"])
def test_the_tool_gate_leaves_a_file_merely_named_like_the_lockfile_open(_repo_root: Path, path: str) -> None:
    assert gatekit.judge(POLICY, _repo_root, gatekit.PRE_TOOL_USE, {path: "x\n"}, {path: "x\n"}) == (0, "")

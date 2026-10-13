"""protect-agent-config: the decision-log settings `.chock/chock-log.json`, in the repository and in `~/.chock/`, are a person's to change."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
gate_script = guardkit.load_guard(POLICY, "protect-agent-config-gate")
pathset = guardkit.load_guard(POLICY, "pathset")

REFUSED = [
    ".chock/chock-log.json",
    "~/.chock/chock-log.json",
    "/Users/dev/.chock/chock-log.json",
    ".CHOCK/Chock-Log.JSON",
    ".chock/chock-log.json:stream",
]
OPEN = ["docs/chock-log.json.md", "chock-log.json", "src/chock-log.json"]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    for name in (".git", ".chock", "docs"):
        (root / name).mkdir(parents=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


@pytest.mark.parametrize("path", REFUSED)
def test_a_shell_write_to_the_log_settings_is_refused(path: str) -> None:
    assert guard.check(f"echo x > {path}") == guard.REASON, path


@pytest.mark.parametrize("path", REFUSED)
def test_the_edit_write_gate_refuses_the_same_file(_repo_root: Path, path: str) -> None:
    assert gate_script.judge(_repo_root, path) == "block", path


@pytest.mark.parametrize("path", OPEN)
def test_a_look_alike_stays_open(_repo_root: Path, path: str) -> None:
    assert pathset.verdict(path) == "", path
    assert guard.check(f"echo x > {path}") is None, path
    assert gate_script.judge(_repo_root, path) == "", path


@pytest.mark.parametrize(
    "raw",
    [
        """echo '{"level": "off"}' > .chock/chock-log.json""",
        "sed -i s/full/off/ .chock/chock-log.json",
        "rm .chock/chock-log.json",
        "rm ~/.chock/chock-log.json",
        "mv .chock/chock-log.json .chock/chock-log.json.bak",
        "jq '.level=\"off\"' x > ~/.chock/chock-log.json",
        "cp quiet.json .chock/chock-log.json",
        "ln -sf empty.json .chock/chock-log.json",
    ],
)
def test_lowering_or_removing_the_log_settings_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize(
    "raw",
    [
        "cat .chock/chock-log.json",
        "jq .level ~/.chock/chock-log.json",
        "grep max_bytes .chock/chock-log.json",
        "git log -p -- .chock/chock-log.json",
        "echo 'see .chock/chock-log.json'",
    ],
)
def test_reads_and_text_that_names_it_pass(raw: str) -> None:
    assert guard.check(raw) is None, raw

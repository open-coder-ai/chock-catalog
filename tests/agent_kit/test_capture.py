"""`kit.py capture` records what an agent really sends its hooks when it edits a file.

chock gates a write before it lands only for agents whose write payload is on record; for the
rest it waits for the turn's end. The capture is how that record grows: a logging hook beside
chock's own, which never objects and never fails, and a summary of what it caught.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import capture
import capture_hook
import kit
import pytest
from workspace import git


def _setup(tmp_path: Path, agent: str = "claude", route: str = "plugin") -> Path:
    workspace = tmp_path / "shop"
    kit.main(["setup", "--dir", str(workspace), "--agent", agent, "--route", route])
    return workspace


def _logger_commands(config: Path) -> list[str]:
    # agentseam 0.3.4's uninstall prunes the `hooks` table it emptied; absent means none left.
    hooks = json.loads(config.read_text(encoding="utf-8")).get("hooks", {})
    entries = [entry for event in hooks.values() for entry in event]
    commands = [hook.get("command", "") for entry in entries for hook in entry.get("hooks", [entry])]
    return [command for command in commands if "capture_hook" in command]


def _call(command: str, payload) -> subprocess.CompletedProcess:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(shlex.split(command), input=text, capture_output=True, text=True, check=False)


EDIT = {
    "hook_event_name": "PreToolUse",
    "tool_name": "Edit",
    "tool_input": {"file_path": "A.java", "old_string": "a", "new_string": "b"},
}


def test_the_logger_records_every_write_event_and_never_objects(tmp_path: Path, capsys) -> None:
    workspace = _setup(tmp_path)
    kit.main(["capture", "--dir", str(workspace)])
    assert "for pre_tool, post_tool, file_changed" in capsys.readouterr().out
    commands = _logger_commands(workspace / ".claude" / "settings.json")
    assert len(commands) == 3
    for payload in (EDIT, "not json at all"):
        done = _call(commands[0], payload)
        assert (done.returncode, done.stdout) == (0, ""), "silence is the one reply every agent reads as allow"
    kit.main(["capture", "--dir", str(workspace), "--show"])
    shown = capsys.readouterr().out
    assert "claude_code  event=PreToolUse  tool=Edit" in shown
    assert '"old_string": "str(1)"' in shown, "the shape, not the content"
    assert "(raw)" in shown
    assert "review before sharing" in shown
    kit.main(["capture", "--dir", str(workspace), "--stop"])
    assert _logger_commands(workspace / ".claude" / "settings.json") == []


def test_an_agent_is_wired_only_for_the_events_it_has(tmp_path: Path, capsys) -> None:
    workspace = _setup(tmp_path, agent="codex")
    kit.main(["capture", "--dir", str(workspace)])
    assert "for pre_tool, post_tool\n" in capsys.readouterr().out
    assert len(_logger_commands(workspace / ".codex" / "hooks.json")) == 2


def test_another_agent_can_be_captured_in_the_same_workspace(tmp_path: Path, capsys) -> None:
    workspace = _setup(tmp_path)
    kit.main(["capture", "--dir", str(workspace), "--vendor", "gemini_cli"])
    assert "gemini_cli: capture hook wired in .gemini/settings.json" in capsys.readouterr().out


@pytest.mark.skipif(shutil.which("chock") is None, reason="the repo route installs with chock")
def test_chocks_own_hooks_stay_and_stop_restores_the_config_exactly(tmp_path: Path) -> None:
    workspace = _setup(tmp_path, route="repo")
    settings = workspace / ".claude" / "settings.json"
    before = settings.read_bytes()
    kit.main(["capture", "--dir", str(workspace)])
    assert settings.read_text(encoding="utf-8").count(".chock/bin/") == before.decode().count(".chock/bin/")
    kit.main(["capture", "--dir", str(workspace), "--stop"])
    assert settings.read_bytes() == before
    assert git(workspace, "status", "--porcelain").stdout == ""


def test_nothing_captured_says_what_to_check(tmp_path: Path) -> None:
    assert "nothing captured yet" in capture.summarise(_setup(tmp_path))[0]


def test_the_logger_survives_being_called_wrongly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO("{}"))
    assert capture_hook.main(["capture_hook.py"]) == 0, "no log path: it still lets the call through"


def test_the_agent_name_defaults_when_not_given(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = tmp_path / "log.jsonl"
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO('{"a": 1}'))
    assert capture_hook.main(["capture_hook.py", str(log)]) == 0
    assert json.loads(log.read_text(encoding="utf-8"))["agent"] == "?"


def test_a_shape_keeps_structure_and_drops_bulk() -> None:
    deep = {"a": {"b": {"c": {"d": 1}}}, "edits": [{"old_string": "xx"}] * 2, "none": [], "n": 3}
    assert capture._shape(deep) == {
        "a": {"b": {"c": "{...}"}},
        "edits": [{"old_string": "str(2)"}, "x2"],
        "none": [],
        "n": "int",
    }


def test_without_agentseam_it_says_what_to_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "agentseam", None)
    with pytest.raises(SystemExit, match="pip install chock"):
        capture.wireable("claude_code")

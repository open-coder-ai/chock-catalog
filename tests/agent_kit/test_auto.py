"""`kit.py auto` runs the manual loop unattended with Claude Code: start, one headless turn, record.

A fake `claude` stands in for the real one here: it writes what a turn would and prints the
stream-json events the real client prints, hook answers included. What the kit then grades is
real -- the engine over the files on disk, as for any agent.
"""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import auto
import kit
import pytest

BAD_SQL = """package com.acme.shop.order;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;

class Leak {
    JdbcTemplate jdbc;
    List<?> find(String customer) {
        return jdbc.queryForList("SELECT * FROM orders WHERE customer = '" + customer + "'");
    }
}
"""

#: Writes FAKE_WRITE's file (path=text as JSON) and prints FAKE_EVENTS, as a turn would.
FAKE = """
import json, os, sys
from pathlib import Path
spec = json.loads(os.environ.get("FAKE_WRITE", "{}"))
for path, text in spec.items():
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8")
Path(os.environ["FAKE_ARGV"]).write_text(json.dumps({"argv": sys.argv[1:], "env": sorted(os.environ)}))
for event in json.loads(os.environ.get("FAKE_EVENTS", "[]")):
    print(json.dumps(event))
print(json.dumps({"type": "result", "result": "done", "is_error": False, "total_cost_usd": 0.01}))
"""


def _hook(event: str, **answer: object) -> dict:
    return {"type": "system", "subtype": "hook_response", "hook_event": event, "exit_code": 0, **answer}


PRE_DENY = _hook("PreToolUse", stdout=json.dumps({"hookSpecificOutput": {"permissionDecision": "deny"}}))
STOP_BLOCK = _hook("Stop", exit_code=2, stderr="[deny: persistence-sql-string-concat]")
#: An agent reading INDEX.md: the refusal message quoted in a tool result is not a refusal.
READ_INDEX = {
    "type": "user",
    "message": {"content": [{"type": "tool_result", "content": "java-security: a construct ... [deny: x]"}]},
}


def test_the_gate_is_read_off_the_hooks_answers_not_off_what_the_agent_read() -> None:
    lines = lambda *events: "\n".join(json.dumps(e) for e in events)  # noqa: E731
    assert auto.gate_seen(lines(PRE_DENY)) == ("refused", "before the write")
    assert auto.gate_seen(lines(STOP_BLOCK)) == ("refused", "at Stop")
    assert auto.gate_seen(lines(PRE_DENY, STOP_BLOCK)) == ("refused", "at Stop, before the write")
    assert auto.gate_seen(lines(READ_INDEX, _hook("PreToolUse"), _hook("Stop"))) == ("silent", "")
    assert auto.gate_seen(lines(_hook("SessionStart", exit_code=1))) == ("silent", "")
    assert auto.gate_seen("not json\n") == ("silent", "")


#: What headless Claude Code actually streams: no PreToolUse/Stop hook_response, only the blocked
#: tool's error result (witnessed on Windows) and the Stop feedback handed back to the model.
EDIT_BLOCKED = {
    "type": "user",
    "message": {
        "content": [
            {
                "type": "tool_result",
                "is_error": True,
                "content": "PreToolUse:Edit hook error: A.java:35: [deny: persistence-sql-string-concat CWE-89]",
            }
        ]
    },
}
STOP_FEEDBACK = {"type": "user", "message": {"content": [{"type": "text", "text": "Stop hook feedback:\n[deny: x]"}]}}
#: A tool that failed for its own reason is no refusal, nor is a file the agent read that opens with
#: either mark: only the client's own text and a blocked tool's error count.
EDIT_FAILED = {
    "type": "user",
    "message": {"content": [{"type": "tool_result", "is_error": True, "content": "File has not been read yet"}]},
}
QUOTED = {
    "type": "user",
    "message": {"content": [{"type": "tool_result", "content": "Stop hook feedback: PreToolUse:Edit hook error"}]},
}


def test_the_gate_is_read_off_the_blocked_tool_when_no_hook_event_is_streamed() -> None:
    lines = lambda *events: "\n".join(json.dumps(e) for e in events)  # noqa: E731
    assert auto.gate_seen(lines(EDIT_BLOCKED)) == ("refused", "before the write")
    assert auto.gate_seen(lines(STOP_FEEDBACK)) == ("refused", "at Stop")
    assert auto.gate_seen(lines(EDIT_BLOCKED, STOP_FEEDBACK)) == ("refused", "at Stop, before the write")
    plain = {"type": "user", "message": {"content": "Stop hook feedback: [deny: x]"}}
    assert auto.gate_seen(lines(plain)) == ("refused", "at Stop")
    assert auto.gate_seen(lines(EDIT_FAILED, QUOTED, READ_INDEX, ["not", "an", "event"])) == ("silent", "")


def test_a_turn_never_reports_into_the_session_that_started_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "parent")
    monkeypatch.setenv("SESSION_INGRESS_URL", "https://parent.invalid")
    monkeypatch.setenv("KEEP_ME", "1")
    env = auto.child_env()
    assert "CLAUDE_CODE_SESSION_ID" not in env
    assert "SESSION_INGRESS_URL" not in env
    assert env["KEEP_ME"] == "1"


@pytest.fixture
def fake_claude(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    script = tmp_path / "fake_claude.py"
    script.write_text(FAKE, encoding="utf-8")
    launcher = tmp_path / "claude"
    launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
    launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("FAKE_ARGV", str(tmp_path / "argv.json"))
    return launcher


def _auto(out: Path, claude: Path, plugin: Path, *extra: str) -> None:
    kit.main(
        ["auto", "--out", str(out), "--route", "plugin", "--plugin-dir", str(plugin), "--claude", str(claude), *extra]
    )


@pytest.mark.skipif(sys.platform == "win32", reason="the fake claude is a shell launcher")
def test_a_turn_is_started_run_and_recorded(
    tmp_path: Path, fake_claude: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    out, plugin = tmp_path / "run", tmp_path / "plugin"
    plugin.mkdir()
    monkeypatch.setenv("FAKE_WRITE", json.dumps({"src/main/java/com/acme/shop/order/Leak.java": BAD_SQL}))
    monkeypatch.setenv("FAKE_EVENTS", json.dumps([STOP_BLOCK]))
    _auto(out, fake_claude, plugin, "--only", "smoke-sql-direct")
    [row] = [json.loads(line) for line in (out / "turns-plugin.jsonl").read_text().splitlines()]
    assert (row["id"], row["gate"], row["where"]) == ("smoke-sql-direct", "refused", "at Stop")
    assert "FAIL" in row["record"], "the agent left the construct on disk: the engine grades it, not the fake"
    assert (out / "transcripts" / "plugin-smoke-sql-direct.jsonl").is_file()
    report = (out / "report.md").read_text()
    assert "| smoke-sql-direct | persistence | FAIL (gate refused" in report
    seen = json.loads((tmp_path / "argv.json").read_text())
    assert seen["argv"][seen["argv"].index("--plugin-dir") + 1] == str(plugin.resolve())
    assert seen["argv"][seen["argv"].index("--setting-sources") + 1] == "project,local"
    assert kit.scenario("smoke-sql-direct")["prompt"].strip() == seen["argv"][1]

    capsys.readouterr()
    _auto(out, fake_claude, plugin, "--only", "smoke-sql-direct")
    assert "0 to run, 1 already recorded" in capsys.readouterr().out, "a recorded scenario is not run again"


def test_a_record_that_failed_is_run_again_not_counted_as_done(
    tmp_path: Path, fake_claude: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    out, plugin = tmp_path / "run", tmp_path / "plugin"
    plugin.mkdir()
    real = auto._kit

    def record_fails(*args: str):
        done = real(*args)
        if args[0] == "record":
            return auto.subprocess.CompletedProcess(args, 1, "", "Traceback ...\nKeyboardInterrupt")
        return done

    monkeypatch.setattr(auto, "_kit", record_fails)
    _auto(out, fake_claude, plugin, "--only", "smoke-sql-direct")
    [row] = [json.loads(line) for line in (out / "turns-plugin.jsonl").read_text().splitlines()]
    assert row["error"].startswith("record failed: ")
    assert "record failed" in capsys.readouterr().out, "the failure is what the worker prints"
    monkeypatch.setattr(auto, "_kit", real)
    _auto(out, fake_claude, plugin, "--only", "smoke-sql-direct")
    assert "1 to run, 0 already recorded" in capsys.readouterr().out, "nothing reached the results: run it again"


def test_the_plugin_route_needs_the_plugin(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="--plugin-dir"):
        kit.main(["auto", "--out", str(tmp_path), "--route", "plugin"])

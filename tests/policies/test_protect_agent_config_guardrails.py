"""protect-agent-config 0.4: the guardrails toggle files, their record and a plugin's install marker are protected."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
gate = guardkit.load_guard(POLICY, "protect-agent-config-gate")

PATHS = [
    ".chock/guardrails.json",
    "~/.chock/guardrails.json",
    ".chock/state/guardrails.sha256",
    "~/.chock/state/guardrails.sha256",
    ".claude/plugins/chock-guardrails/chock.selection.json",
    "plugins/chock-guardrails/chock.selection.json",
    "~/.cursor/plugins/local/chock-guardrails/chock.selection.json",
]
SPELLINGS = [
    ".CHOCK/Guardrails.JSON",
    ".chock/x/../guardrails.json",
    ".chock/state/guardrails.sha256.",
    "plugins/p/CHOCK.Selection.json",
    "plugins/p/./chock.selection.json",
]
LOOK_ALIKES = ["plugins/p/chock.selection.json5", "plugins/p/my-chock.selection.json", "guardrails.json"]


@pytest.mark.parametrize("path", PATHS + SPELLINGS)
@pytest.mark.parametrize("write", ["echo x > {}", "echo x >> {}", "tee {}", "cp evil.json {}", "mv evil.json {}"])
def test_a_shell_write_is_refused(path: str, write: str) -> None:
    assert guard.check(write.format(path)) == guard.REASON


@pytest.mark.parametrize("path", PATHS + SPELLINGS)
@pytest.mark.parametrize("read", ["cat {}", "jq . {}", "jq -r .bundles {}", "sha256sum {}"])
def test_a_read_is_allowed(path: str, read: str) -> None:
    assert guard.check(read.format(path)) is None


@pytest.mark.parametrize("path", LOOK_ALIKES)
def test_a_look_alike_name_stays_open(path: str, tmp_path: Path) -> None:
    assert guard.check(f"echo x > {path}") is None
    assert gate.judge(tmp_path, path) == ""


@pytest.mark.parametrize(
    "path",
    [
        ".chock/guardrails.json",
        ".chock/state/guardrails.sha256",
        ".CHOCK/STATE/GUARDRAILS.SHA256",
        ".chock/state/x/../guardrails.sha256",
        "plugins/p/chock.selection.json",
        "/home/dev/.chock/guardrails.json",
        "/home/dev/.chock/state/guardrails.sha256",
    ],
)
def test_an_edit_or_write_is_refused(path: str, tmp_path: Path) -> None:
    assert gate.judge(tmp_path, path) == "block"


def test_the_engine_s_own_files_stay_open_to_the_gate(tmp_path: Path) -> None:
    assert gate.judge(tmp_path, ".chock/state/session.log") == ""
    assert gate.judge(tmp_path, ".chock/log/gates.jsonl") == ""


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
@pytest.mark.parametrize(
    "target",
    [".chock/state/guardrails.sha256", ".chock/guardrails.json", ".claude/settings.json", "p/chock.selection.json"],
)
def test_a_link_below_the_engine_s_own_folder_is_judged_by_its_target(target: str, tmp_path: Path) -> None:
    (tmp_path / ".chock/state").mkdir(parents=True)
    (tmp_path / ".chock/state/innocent.log").symlink_to(tmp_path / target)
    assert gate.judge(tmp_path, ".chock/state/innocent.log") == "block"


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_shell_write_through_a_link_to_the_marker_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "p").mkdir()
    (tmp_path / "p/chock.selection.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "notes.json").symlink_to(tmp_path / "p/chock.selection.json")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    assert guard.check("echo x > notes.json") == guard.REASON
    assert gate.judge(tmp_path, "notes.json") == "block"

"""The plugin route: a plain repository, and only the gate the installed plugin brings.

Most adopters never run `chock init`: they install java-security from their agent's marketplace
into an ordinary repository and start working. The doctor proves that gate before a scenario is
spent on it. Checked against the real thing: the plugin published at 0.3.0 has no JDBC rule and
fails, a 0.4.3 plugin built with chock 0.11.3 refuses a Write but lets the same Edit through, and
one built with the Edit fix passes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import doctor
import kit
import plugin_route
import pytest

#: A hook that judges only the call's own text, the way chock before 0.11.4 judged an edit: the
#: Write carries the imports the SQL rule needs, the Edit's bare fragment does not.
FRAGMENT_JUDGE = """
import json, sys
ti = json.load(sys.stdin)["tool_input"]
text = ti.get("content", ti.get("new_string", ""))
if "import org.springframework" in text and "+ customer +" in text:
    print(json.dumps({"hookSpecificOutput": {"permissionDecision": "deny"}}))
"""
#: A hook that sees the whole file an edit would leave, as 0.11.4 does.
WHOLE_FILE_JUDGE = """
import json, sys
ti = json.load(sys.stdin)["tool_input"]
text = ti.get("content") or open(ti["file_path"], encoding="utf-8").read().replace(ti["old_string"], ti["new_string"])
if "+ customer +" in text:
    print(json.dumps({"hookSpecificOutput": {"permissionDecision": "deny"}}))
"""


def _plain(tmp_path: Path) -> Path:
    workspace = tmp_path / "shop"
    kit.main(["setup", "--dir", str(workspace), "--agent", "claude", "--route", "plugin"])
    return workspace


def _plugin(root: Path, version: str = "", judge: str = WHOLE_FILE_JUDGE, interpreter: str = "") -> Path:
    """A Claude-format plugin laid out as a marketplace install leaves it, at this catalog's version by default."""
    version = version or ".".join(map(str, plugin_route.catalog_version()))
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "java-security", "version": version}))
    (root / "scripts").mkdir()
    (root / "scripts" / "hook.py").write_text(judge, encoding="utf-8")
    command = f'"{interpreter or sys.executable}" "${{CLAUDE_PLUGIN_ROOT}}/scripts/hook.py"'
    hooks = {"hooks": {"PreToolUse": [{"matcher": "Write|Edit|MultiEdit", "hooks": [{"command": command}]}]}}
    (root / "hooks").mkdir()
    (root / "hooks" / "hooks.json").write_text(json.dumps(hooks), encoding="utf-8")
    return root


def _doctor(workspace: Path, plugin: Path | None, capsys) -> tuple[bool, str]:
    argv = ["doctor", "--dir", str(workspace)] + (["--plugin-dir", str(plugin)] if plugin else [])
    try:
        kit.main(argv)
    except SystemExit:
        return False, capsys.readouterr().out
    return True, capsys.readouterr().out


def test_setup_leaves_a_repository_with_nothing_of_chocks_in_it(tmp_path: Path) -> None:
    workspace = _plain(tmp_path)
    assert not [name for name in plugin_route.CHOCK_FILES if (workspace / name).exists()]
    assert not (workspace / ".git" / "hooks" / "pre-commit").exists()


def test_a_current_plugin_that_judges_the_whole_file_passes(tmp_path: Path, capsys) -> None:
    workspace = _plain(tmp_path)
    ok, out = _doctor(workspace, _plugin(tmp_path / "plugin"), capsys)
    assert ok, out
    assert "allows the fix (Write)" in out
    assert "allows the fix (Edit)" in out
    assert not (workspace / doctor.PROBE).exists(), "the probe file is removed again"


def test_a_plugin_that_judges_an_edits_fragment_is_caught(tmp_path: Path, capsys) -> None:
    ok, out = _doctor(_plain(tmp_path), _plugin(tmp_path / "plugin", judge=FRAGMENT_JUDGE), capsys)
    assert not ok
    assert "ok    the plugin's hook denies the construct, allows the fix (Write)" in out
    assert "FAIL  the plugin's hook denies the construct, allows the fix (Edit)" in out


def test_a_plugin_older_than_the_catalog_is_caught(tmp_path: Path, capsys) -> None:
    ok, out = _doctor(_plain(tmp_path), _plugin(tmp_path / "plugin", version="0.3.0"), capsys)
    assert not ok
    assert "FAIL  the installed plugin (0.3.0" in out


def test_a_hook_whose_interpreter_is_not_on_path_is_caught(tmp_path: Path, capsys) -> None:
    """The plugin's hook runs `python3`, which a Windows machine often does not have."""
    ok, out = _doctor(_plain(tmp_path), _plugin(tmp_path / "plugin", interpreter="python3-not-installed"), capsys)
    assert not ok
    assert "FAIL  the hook's interpreter `python3-not-installed` is on PATH" in out


def test_a_plugin_with_no_write_hook_is_caught(tmp_path: Path, capsys) -> None:
    plugin = _plugin(tmp_path / "plugin")
    (plugin / "hooks" / "hooks.json").write_text(json.dumps({"hooks": {"Stop": []}}), encoding="utf-8")
    ok, out = _doctor(_plain(tmp_path), plugin, capsys)
    assert not ok
    assert "FAIL  the plugin has a PreToolUse hook for writes" in out


def test_the_plugin_is_found_in_claude_codes_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    home = tmp_path / "home"
    store = home / ".claude" / "plugins" / "marketplaces" / "chock" / "claude"
    _plugin(store / "java-security-old", version="0.3.0")
    newest = _plugin(store / "java-security")
    _plugin(store / "other", version="9.9.9").joinpath(".claude-plugin", "plugin.json").write_text(
        json.dumps({"name": "block-no-verify", "version": "9.9.9"})
    )
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    assert plugin_route.installed(home)[0] == newest
    ok, out = _doctor(_plain(tmp_path), None, capsys)
    assert ok, out


def test_no_plugin_installed_says_how_to_install_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "empty-home"))
    ok, out = _doctor(_plain(tmp_path), None, capsys)
    assert not ok
    assert "/plugin install java-security@chock" in out


def test_a_bootstrapped_repository_is_not_the_plain_scenario(tmp_path: Path, capsys) -> None:
    workspace = _plain(tmp_path)
    (workspace / ".chock").mkdir()
    ok, out = _doctor(workspace, _plugin(tmp_path / "plugin"), capsys)
    assert not ok
    assert "FAIL  the repository is plain" in out


def test_other_agents_are_checked_for_a_plain_repository_only(tmp_path: Path) -> None:
    workspace = _plain(tmp_path)
    results = plugin_route.checks(workspace, {"agent": "copilot", "route": "plugin"})
    assert [held for _, held, _ in results] == [True, True]
    assert "install java-security from its marketplace" in results[1][0]


def test_the_catalog_version_is_read_from_the_manifest() -> None:
    assert plugin_route.catalog_version() >= (0, 4, 3)

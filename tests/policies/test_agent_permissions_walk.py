"""agent-permissions-scan: the walker over parsed configs, and the waiver sidecar's closed schema."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from policies import scriptkit
from policies.permskit import load, sidecar, walk

# --- walk ----------------------------------------------------------------------------------------------------


def rules_of(tree: object, surface: str = "claude", hidden: tuple = ()) -> list[tuple[str, str, str]]:
    return [(h.rule, h.path, h.value) for h in walk.hits(tree, surface, hidden)]


def test_allow_lists_name_each_broad_entry_without_list_indexes() -> None:
    tree = {"permissions": dict(allow=["Read", "*", "Bash(curl:*)", 5, "Bash(npm test:*)"], ask=["Bash"])}
    assert rules_of(tree) == [
        (walk.ALLOW, "permissions.allow", "*"),
        (walk.ALLOW, "permissions.allow", "Bash(curl:*)"),
    ]
    assert rules_of({"allowedTools": "Bash"}) == [(walk.ALLOW, "allowedTools", "Bash")]
    assert rules_of({"allow": True}) == []
    assert rules_of({"mcpServers": {"s": {"autoApprove": ["*"]}}}) == [(walk.ALLOW, "mcpServers.s.autoApprove", "*")]
    assert rules_of(dict(tools=["*"])) == [(walk.ALLOW, "tools", "*")]


@pytest.mark.parametrize("value", ["bypassPermissions", "BYPASSPERMISSIONS", "bypass_permissions", " yolo ", "Auto"])
def test_dangerous_modes_in_any_case(value: str) -> None:
    assert rules_of({"permissions": {"defaultMode": value}})[0][0] == walk.MODE
    assert rules_of({"general": {"default_approval_mode": value}})[0][0] == walk.MODE


@pytest.mark.parametrize("value", ["default", "acceptEdits", "plan", 5, None])
def test_asking_modes_pass(value: object) -> None:
    assert rules_of({"permissions": {"defaultMode": value}}) == []


def test_switches_and_skip_flags() -> None:
    assert rules_of({"yes-always": True}, "aider") == [(walk.FLAG, "yes-always", "true")]
    assert rules_of({"yes_always": "yes"}, "aider")[0][0] == walk.FLAG
    assert rules_of({"yes-always": False}, "aider") == []
    assert rules_of({"ui": {"autoAccept": True}}, "gemini") == [(walk.FLAG, "ui.autoAccept", "true")]
    assert rules_of({"chat.tools.autoApprove": True}, "vscode") == [(walk.FLAG, "chat.tools.autoApprove", "true")]
    assert rules_of({"claudeCode.allowDangerouslySkipPermissions": True}, "vscode")[0][0] == walk.FLAG
    found = rules_of({"hooks": [{"command": "claude --dangerously-skip-permissions -p go"}]})
    assert found == [(walk.SKIP, "hooks.command", "--dangerously-skip-permissions")]


def test_gemini_trust_and_folder_trust() -> None:
    assert rules_of({"mcpServers": {"s": {"trust": True}}}, "gemini") == [(walk.FLAG, "mcpServers.s.trust", "true")]
    assert rules_of({"mcpServers": {"s": {"trust": True}}}, "claude") == []
    assert rules_of({"security": {"folderTrust": {"enabled": False}}}, "gemini") == [
        (walk.FLAG, "security.folderTrust.enabled", "false")
    ]
    assert rules_of({"security": {"folderTrust": {"enabled": True}}}, "gemini") == []
    assert rules_of({"security": {"folderTrust": True}}, "gemini") == []


def test_vscode_auto_approve_rules() -> None:
    terminal = {
        "chat.tools.terminal.autoApprove": {
            "/.*/": True,
            "rm": {"approve": True},
            "/^curl\\b/": True,
            "git status": True,
            "sudo": False,
            "wget": {"approve": False},
        }
    }
    assert rules_of(terminal, "vscode") == [
        (walk.VSCODE, "chat.tools.terminal.autoApprove", "/.*/"),
        (walk.VSCODE, "chat.tools.terminal.autoApprove", "rm"),
        (walk.VSCODE, "chat.tools.terminal.autoApprove", "/^curl\\b/"),
    ]
    urls = {"chat.tools.urls.autoApprove": {"*": True, "https://example.com": True}}
    assert rules_of(urls, "vscode") == [(walk.VSCODE, "chat.tools.urls.autoApprove", "*")]


def test_opencode_permissions() -> None:
    tree = {
        "permission": {
            "bash": "allow",
            "edit": {"*": "allow"},
            "webfetch": "ask",
            "read": "allow",
            "write": {"*": "ask"},
        }
    }
    assert rules_of(tree, "opencode") == [
        (walk.ALLOW, "permission", "bash=allow"),
        (walk.ALLOW, "permission", "edit=allow"),
    ]
    assert rules_of({"permission": "allow"}, "opencode") == [(walk.ALLOW, "permission", "*=allow")]
    assert rules_of({"permission": ["allow"]}, "opencode") == []
    assert rules_of({"permission": {"bash": "allow"}}, "claude") == []


def test_codex_needs_both_in_one_effective_profile() -> None:
    both = {"approval_policy": "never", "sandbox_mode": "danger-full-access"}
    assert rules_of(both, "codex") == [(walk.CODEX, "<root>", "never+danger-full-access")]
    assert rules_of({"approval_policy": "Never", "sandbox_mode": "DANGER_FULL_ACCESS"}, "codex")
    assert rules_of({"approval_policy": "never", "sandbox_mode": "workspace-write"}, "codex") == []
    assert rules_of({"approval_policy": "on-request", "sandbox_mode": "danger-full-access"}, "codex") == []
    inherited = {
        "approval_policy": "never",
        "profiles": {"ci": {"sandbox_mode": "danger-full-access"}, "ok": {"sandbox_mode": "read-only"}},
    }
    assert rules_of(inherited, "codex") == [(walk.CODEX, "profiles.ci", "never+danger-full-access")]
    assert rules_of({"profiles": {"x": 5}}, "codex") == []
    assert rules_of({"profiles": 5}, "codex") == []
    assert walk.hits([both], "codex") == []


def test_hidden_duplicate_values_are_judged_too() -> None:
    parsed = load.parse(
        "json",
        '{"permissions": {"defaultMode": "auto", "defaultMode": "default"}}',
    )
    assert rules_of(parsed.tree, "claude", parsed.hidden) == [(walk.MODE, "permissions.defaultMode", "auto")]
    nested = load.parse("json", '{"permissions": {"allow": ["Bash"], "allow": []}}')
    assert rules_of(nested.tree, "claude", nested.hidden) == [(walk.ALLOW, "permissions.allow", "Bash")]


def test_denies_are_counted_per_surface_path() -> None:
    assert walk.denies({"permissions": {"deny": ["Read(.env)", "Read(.env)", "Bash(rm:*)", 5]}}, "claude") == {
        ("permissions.deny", "Read(.env)"): 2,
        ("permissions.deny", "Bash(rm:*)"): 1,
    }
    assert walk.denies({"tools": {"exclude": ["run_shell_command"]}, "excludeTools": "x"}, "gemini") == {
        ("tools.exclude", "run_shell_command"): 1,
        ("excludeTools", "x"): 1,
    }
    assert walk.denies({"permissions": {"deny": ["x"]}}, "vscode") == {}
    assert walk.denies([], "claude") == {}
    assert walk.denies({"permissions": 5}, "claude") == {}


# --- sidecar -------------------------------------------------------------------------------------------------


def test_waivers_read_the_closed_schema() -> None:
    text = json.dumps({"waive": [{"file": "./.claude\\settings.json", "path": "p", "value": "v"}]})
    assert sidecar.waivers(text) == {(".claude/settings.json", "p", "v")}
    assert sidecar.waivers("{}") == frozenset()


@pytest.mark.parametrize(
    "text",
    [
        "{",
        "[]",
        '{"waive": [], "extra": 1}',
        '{"waive": {}}',
        '{"waive": [5]}',
        '{"waive": [{"file": "a", "path": "b"}]}',
        '{"waive": [{"file": "a", "path": "b", "value": "c", "why": "d"}]}',
        '{"waive": [{"file": "a", "path": "b", "value": 3}]}',
        '{"waive": [], "waive": []}',
    ],
)
def test_waivers_refuse_anything_else(text: str) -> None:
    with pytest.raises(sidecar.SidecarError):
        sidecar.waivers(text)


def test_committed_reads_head_and_survives_a_missing_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = scriptkit.init_repo(tmp_path / "c", {"a/b.txt": "hello\n"})
    assert sidecar.committed(repo, "a/b.txt") == "hello\n"
    assert sidecar.committed(repo, "missing.txt") is None

    def boom(*_a: object, **_k: object) -> None:
        raise OSError

    monkeypatch.setattr(subprocess, "run", boom)
    assert sidecar.committed(repo, "a/b.txt") is None


def test_a_ban_on_a_flag_is_not_a_grant_of_it() -> None:
    tree = {"permissions": {"deny": ["Bash(claude --dangerously-skip-permissions:*)"], "ask": ["Bash(* --yolo*)"]}}
    assert rules_of(tree) == []
    assert rules_of({"exclude": ["--yolo"]}, "continue") == []


def test_vscode_keys_count_only_for_agent_extensions() -> None:
    assert rules_of({"editor.defaultMode": "auto", "gitlens.autoApprove": True}, "vscode") == []
    assert rules_of({"cline.autoApprove": True, "claudeCode.initialPermissionMode": "auto"}, "vscode") != []


def test_a_grant_repeated_in_two_places_is_reported_twice_but_a_hidden_copy_of_the_last_value_is_not() -> None:
    tree = {"a": {"autoApprove": ["*"]}, "b": [{"autoApprove": ["*"]}]}
    assert rules_of(tree) == [(walk.ALLOW, "a.autoApprove", "*"), (walk.ALLOW, "b.autoApprove", "*")]
    twice = {"x": [{"allow": ["Bash"]}, {"allow": ["Bash"]}]}
    assert rules_of(twice) == [(walk.ALLOW, "x.allow", "Bash")] * 2
    parsed = load.parse("json", '{"allow": ["Bash"], "allow": ["Bash"]}')
    assert rules_of(parsed.tree, "claude", parsed.hidden) == [(walk.ALLOW, "allow", "Bash")]


def test_opencode_denies() -> None:
    tree = {"permission": {"bash": {"rm *": "deny", "ls": "allow"}, "edit": "deny", "read": "allow"}}
    assert walk.denies(tree, "opencode") == {("permission.bash", "rm *"): 1, ("permission", "edit"): 1}
    assert walk.denies({"permission": "deny"}, "opencode") == {}
    assert walk.denies({"permission": 5}, "opencode") == {}


def test_a_server_or_key_named_like_a_ban_does_not_hide_a_grant() -> None:
    assert rules_of({"mcpServers": {"exclude": {"trust": True}}}, "gemini") == [
        (walk.FLAG, "mcpServers.exclude.trust", "true")
    ]
    nested = {"permissions": {"ask": {"defaultMode": "auto"}, "Deny": {"allow": ["Bash"]}}}
    assert rules_of(nested) == [
        (walk.MODE, "permissions.ask.defaultMode", "auto"),
        (walk.ALLOW, "permissions.Deny.allow", "Bash"),
    ]


def test_agent_extension_keys_are_read_by_their_last_segment() -> None:
    tree = {"roo-cline.allowedCommands": ["*"], "amp.dangerouslyAllowAll": True, "kilo-code.autoApprove": True}
    assert [hit.path for hit in walk.hits(tree, "vscode")] == [
        "roo-cline.allowedCommands",
        "amp.dangerouslyAllowAll",
        "kilo-code.autoApprove",
    ]

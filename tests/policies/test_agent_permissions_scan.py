"""agent-permissions-scan: the script gate that judges agent permission configs; rules, parsers, sidecar and engine."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from policies import gatekit, scriptkit

POLICY = "agent-permissions-scan"
NAME = "agent-permissions-scan.py"
mod = scriptkit.load(POLICY, NAME)
from perms import load, rules, sidecar, walk  # noqa: E402  (importable once the script put its folder on sys.path)

CLAUDE = ".claude/settings.json"


def settings(**permissions: object) -> str:
    return json.dumps({"permissions": permissions}, indent=2)


def payload(repo: Path, writes: dict[str, str], event: str = "commit", **extra: object) -> dict:
    return {"event": event, "repo_root": str(repo), "writes": writes, **extra}


def keys(repo: Path, writes: dict[str, str], event: str = "commit", **extra: object) -> list[str]:
    return [f["key"] for f in mod.findings(payload(repo, writes, event, **extra))]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return scriptkit.init_repo(tmp_path / "r", {"README.md": "x\n"})


def held(tmp_path: Path, files: dict[str, str]) -> Path:
    return scriptkit.init_repo(tmp_path / "h", files)


# --- rules ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry",
    [
        "*",
        "**",
        "Bash",
        "Bash()",
        "Bash(**)",
        "Bash(:*)",
        "Bash( * )",
        "Bash(*curl*)",
        "Bash(: *x)",
        "Bash(curl:*)",
        "Bash(curl *)",
        "Bash(curl*)",
        "Bash(rm -rf:*)",
        "Bash(sudo:*)",
        "Bash(git push:*)",
        "Bash(/usr/bin/curl:*)",
        "Bash(bash:*)",
        "Shell(*)",
        "run_shell_command",
        "WebFetch",
        "WebFetch(*)",
        "WebFetch(domain:*)",
        "Write",
        "Write(**)",
        "Write(/**)",
        "Write(//**)",
        "Edit(**/*)",
        "Edit(~/**)",
        "Edit(~/.ssh/config)",
        "Write(//etc/**)",
        "MultiEdit",
        "mcp__*",
        "mcp__server__*",
        "mcp__*__read",
        "mcp__server",
        "  Bash( curl:* )  ",
    ],
)
def test_broad_entries_are_named(entry: str) -> None:
    assert rules.broad_entry(entry)


@pytest.mark.parametrize(
    "entry",
    [
        "Read",
        "Grep",
        "Glob",
        "WebSearch",
        "Read(//**)",
        "Bash(npm test:*)",
        "Bash(git status:*)",
        "Bash(git push)",
        "Bash(curl https://api.example.com/v1)",
        "Bash(rm build/out.txt)",
        "Bash(make:*)",
        "WebFetch(domain:example.com)",
        "Write(src/**)",
        "Edit(./docs/**)",
        "Edit(/src/**)",
        "mcp__server__tool",
        "Bash(unclosed",
        "not an entry!",
        "",
    ],
)
def test_scoped_entries_are_not(entry: str) -> None:
    assert rules.broad_entry(entry) is None


def test_the_messages_name_the_command() -> None:
    assert rules.broad_entry("Bash(git push origin:*)") == "a wildcard over git push"
    assert rules.broad_entry("Bash(curl:*)") == "a wildcard over curl"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        ("true", True),
        (" YES ", True),
        ("on", True),
        ("1", True),
        (1, True),
        (False, False),
        ("false", False),
        (0, False),
        (2, False),
        (None, False),
        ([], False),
    ],
)
def test_truthy(value: object, expected: bool) -> None:
    assert rules.truthy(value) is expected


def test_norm_and_letters() -> None:
    assert rules.norm("a \n  b") == "a b"
    long = "x" * 300
    assert rules.norm(long).startswith("x" * 160 + "...#")
    assert rules.norm(long) != rules.norm("x" * 299 + "y")
    assert rules.letters("Bypass_Permissions-") == "bypasspermissions"


def test_skip_flags() -> None:
    assert rules.skip_flag("claude --dangerously-skip-permissions -p x") == "--dangerously-skip-permissions"
    assert rules.skip_flag("codex --dangerously-bypass-approvals-and-sandbox")
    assert rules.skip_flag("gemini --yolo")
    assert rules.skip_flag("q chat --trust-all-tools")
    assert rules.skip_flag("claude --permission-mode=bypassPermissions")
    assert rules.skip_flag("gemini --approval-mode yolo")
    assert rules.skip_flag("claude --permission-mode plan") is None
    assert rules.skip_flag("echo hello") is None


@pytest.mark.parametrize("pattern", ["/.*/", "/.+/i", "/^.*$/", "/(?:)/", "/\\S+/", "/[\\s\\S]*/", "//"])
def test_regex_all(pattern: str) -> None:
    assert rules.regex_all(pattern)


@pytest.mark.parametrize("pattern", ["/^git status$/", "/usr/bin/rm", ".*", "git", "/foo/ bar"])
def test_regex_not_all(pattern: str) -> None:
    assert not rules.regex_all(pattern)


def test_rule_command_and_broad_globs() -> None:
    assert [rules.rule_command(p) for p in ("curl", "/^curl\\b/", "/curl .*/", "/usr/bin/rm", "!!!", "")] == [
        "curl",
        "curl",
        "curl",
        "rm",
        "",
        "",
    ]
    assert all(rules.broad_url_or_glob(p) for p in ("*", "**/*", "https://*", "/", ""))
    assert not any(rules.broad_url_or_glob(p) for p in ("**/*.ts", "https://example.com", "src/**"))


# --- load ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (".claude/settings.json", ("json", "claude")),
        ("pkg/.claude/settings.local.json", ("json", "claude")),
        (".Claude\\Settings.JSON", ("json", "claude")),
        ("./.gemini/settings.json", ("json", "gemini")),
        (".vscode/settings.json", ("json", "vscode")),
        ("a/b.code-workspace", ("json", "vscode")),
        (".cursor/cli.json", ("json", "cursor")),
        ("opencode.json", ("json", "opencode")),
        ("x/opencode.jsonc", ("json", "opencode")),
        (".codex/config.toml", ("toml", "codex")),
        (".aider.conf.yml", ("yaml", "aider")),
        ("sub/.aider.conf.yaml", ("yaml", "aider")),
        (".continue/config.yaml", ("yaml", "continue")),
        (".continue/a/b.yml", ("yaml", "continue")),
        (".continue/config.json", ("json", "continue")),
    ],
)
def test_classify(path: str, expected: tuple[str, str]) -> None:
    assert load.classify(path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "package.json",
        ".claude/settings.json.bak",
        ".claude/commands/x.md",
        ".continue/rules.md",
        "settings.json",
        ".vscode/tasks.json",
        ".mcp.json",
        "claude/settings.json",
        ".codex/config.json",
    ],
)
def test_classify_ignores(path: str) -> None:
    assert load.classify(path) is None


def test_parse_json_reads_jsonc_and_reports_hidden_duplicates() -> None:
    parsed = load.parse("json", '// c\n{"a": 1, /* x */ "b": [1, 2,], "a": 2,}\n')
    assert parsed.tree == {"a": 2, "b": [1, 2]}
    assert [(path, value) for path, value in parsed.hidden] == [(("a",), 1), (("a",), 2)]
    assert load.parse("json", '{"\\u0064efaultMode": "x"}').tree == {"defaultMode": "x"}


@pytest.mark.parametrize(
    ("kind", "text"),
    [
        ("json", "{"),
        ("json", '{"a": 1} x'),
        ("toml", "= ="),
        ("yaml", "a: ["),
        ("yaml", "\t- x: 1\n"),
        ("yaml", "a: 'x"),
    ],
)
def test_parse_refuses_what_it_cannot_read(kind: str, text: str) -> None:
    with pytest.raises(load.UnreadableError):
        load.parse(kind, text)


def test_parse_yaml_trees() -> None:
    assert load.parse("yaml", "a: 1\nb:\n  - x\n  - y: 2\n  - [p, q]\nc: {d: e}\n").tree == {
        "a": "1",
        "b": ["x", {"y": "2"}, ["p", "q"]],
        "c": {"d": "e"},
    }
    assert load.parse("yaml", "- a\n- b\n").tree == ["a", "b"]
    assert load.parse("yaml", "just text\n").tree == "just text"
    assert load.parse("yaml", "").tree == {}
    assert load.parse("toml", 'a = "x"\n[t]\nb = 1\n').tree == {"a": "x", "t": {"b": 1}}


@pytest.mark.parametrize(
    "text",
    ["a: &x 1\nb: *x\n", "a: 1\na: 2\n", "base: &b {x: 1}\nd:\n  <<: *b\n", "a: 1\n---\nb: 2\n"],
)
def test_parse_yaml_refuses_aliases_repeats_and_many_documents(text: str) -> None:
    with pytest.raises(load.UnreadableError):
        load.parse("yaml", text)


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


# --- the script ----------------------------------------------------------------------------------------------


def test_the_manifest_declares_a_script_gate_that_only_warns() -> None:
    manifest = scriptkit.manifest(POLICY)
    gate = manifest["hook"]["gate"]
    assert (gate["kind"], gate["on"], gate["action"], gate["params"]) == (
        "script",
        ["commit", "tool_use"],
        "warn",
        {"script": NAME},
    )
    assert (manifest["artifact"], manifest["enforcement"]) == ("rule", "advise")
    assert len(manifest["description"]) <= 500


def test_a_clean_scoped_config_has_no_findings(repo: Path) -> None:
    writes = {CLAUDE: settings(allow=["Read", "Bash(npm test:*)", "WebFetch(domain:example.com)"], deny=["Read(.env)"])}
    assert mod.findings(payload(repo, writes)) == []
    assert (
        mod.findings(
            payload(
                repo,
                {
                    "package.json": json.dumps(dict(allow=["*"])),
                    "notes.md": "defaultMode: bypassPermissions",
                },
            )
        )
        == []
    )


def test_findings_are_keyed_by_rule_path_and_value_and_never_by_line(repo: Path) -> None:
    text = json.dumps({"permissions": dict(allow=["Read", "*"])}, indent=2) + "\n"
    (found,) = mod.findings(payload(repo, {CLAUDE: text}))
    assert found["key"] == "ap-allow-broad|permissions.allow|*"
    assert (found["path"], found["line"], found["new"]) == (CLAUDE, 5, False)
    shifted = mod.findings(payload(repo, {CLAUDE: "\n\n" + text.replace('"Read",', '"Read", "Grep",')}))
    assert [f["key"] for f in shifted] == [found["key"]]


def test_a_value_escaped_in_the_text_still_gets_a_line(repo: Path) -> None:
    (found,) = mod.findings(payload(repo, {CLAUDE: '{\n"\\u0064efaultMode": "bypassPermissions"}'}))
    assert (found["key"], found["line"]) == ("ap-mode-bypass|defaultMode|bypassPermissions", 2)
    (other,) = mod.findings(payload(repo, {CLAUDE: '{\n"defaultMode": "\\u0062ypassPermissions"}'}))
    assert other["line"] == 2


def test_an_unreadable_config_is_one_finding_keyed_by_its_text(repo: Path) -> None:
    (found,) = mod.findings(payload(repo, {CLAUDE: '{"permissions": '}))
    assert found["key"].startswith("ap-unreadable|<file>|")
    assert "cannot be read" in found["message"]
    other = mod.findings(payload(repo, {CLAUDE: '{"permissions": }'}))
    assert other[0]["key"] != found["key"]


def test_duplicate_keys_are_judged_in_either_order(repo: Path) -> None:
    bypass_last = '{"permissions": {"defaultMode": "default", "defaultMode": "auto"}}'
    bypass_first = '{"permissions": {"defaultMode": "auto", "defaultMode": "default"}}'
    assert keys(repo, {CLAUDE: bypass_last}) == ["ap-mode-bypass|permissions.defaultMode|auto"]
    assert keys(repo, {CLAUDE: bypass_first}) == ["ap-mode-bypass|permissions.defaultMode|auto"]
    assert keys(repo, {CLAUDE: '{"permissions": {"defaultMode": "default", "defaultMode": "plan"}}'}) == []


def test_comments_and_trailing_commas_do_not_hide_a_grant(repo: Path) -> None:
    text = '// team settings\n{\n  /* shell */\n  "permissions": {"allow": [\n    "Bash", // everything\n  ],},\n}\n'
    assert keys(repo, {CLAUDE: text}) == ["ap-allow-broad|permissions.allow|Bash"]


def test_every_surface_is_read(repo: Path) -> None:
    writes = {
        ".codex/config.toml": 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n',
        ".gemini/settings.json": '{"general": {"defaultApprovalMode": "yolo"}}',
        ".vscode/settings.json": '{"chat.tools.terminal.autoApprove": {"/.*/": true}}',
        ".aider.conf.yml": "yes-always: true\n",
        ".continue/config.yaml": "defaultMode: bypassPermissions\n",
        ".cursor/cli.json": '{"permissions": {"allow": ["Shell(*)"]}}',
        "opencode.json": '{"permission": {"bash": "allow"}}',
    }
    found = {f["path"] for f in mod.findings(payload(repo, writes))}
    assert found == set(writes)


def test_baseline_runs_skip_the_deny_comparison(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: settings(deny=["Read(.env)"])})
    assert keys(base, {CLAUDE: settings(allow=["Read"])}) == ["ap-deny-removed|permissions.deny|Read(.env)"]
    assert keys(base, {CLAUDE: settings(allow=["Read"])}, baseline=True) == []


def test_a_removed_deny_entry_is_always_new_and_a_kept_one_is_not(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: settings(deny=["Read(.env)", "Bash(rm:*)", "Bash(rm:*)"])})
    (gone,) = mod.findings(
        payload(base, {CLAUDE: settings(deny=["Read(.env)", "Bash(rm:*)", "Bash(rm:*)", "Edit"])})
        | {"writes": {CLAUDE: settings(deny=["Bash(rm:*)", "Bash(rm:*)"])}}
    )
    assert (gone["key"], gone["new"], gone["line"]) == ("ap-deny-removed|permissions.deny|Read(.env)", True, 1)
    assert keys(base, {CLAUDE: settings(deny=["Read(.env)", "Bash(rm:*)", "Bash(rm:*)"], allow=["Read"])}) == []
    assert keys(base, {CLAUDE: settings(deny=["Read(.env)", "Bash(rm:*)"])}) == [
        "ap-deny-removed|permissions.deny|Bash(rm:*)"
    ]


def test_deny_shrinkage_is_read_on_disk_at_tool_use_and_ignores_unreadable_texts(tmp_path: Path) -> None:
    base = held(tmp_path, {"README.md": "x\n"})
    scriptkit.write(base, {CLAUDE: settings(deny=["Read(.env)"])})
    write = {CLAUDE: settings()}
    assert keys(base, write, "tool_use") == ["ap-deny-removed|permissions.deny|Read(.env)"]
    assert keys(base, write, "commit") == []
    scriptkit.write(base, {CLAUDE: "not json"})
    assert keys(base, write, "tool_use") == []
    (base / CLAUDE).unlink()
    assert keys(base, write, "tool_use") == []
    outside = {"../" + CLAUDE: settings()}
    assert keys(base, outside, "tool_use") == []


def test_head_text_that_cannot_be_read_is_not_a_deny_baseline(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: "{ nope"})
    assert keys(base, {CLAUDE: settings(allow=["Read"])}) == []


def waiver_file(*items: dict) -> str:
    return json.dumps({"waive": list(items)})


GRANT = {CLAUDE: settings(allow=["Bash(curl:*)"])}
WAIVE = {"file": CLAUDE, "path": "permissions.allow", "value": "Bash(curl:*)"}


def test_a_waiver_in_head_clears_exactly_its_finding(tmp_path: Path) -> None:
    base = held(tmp_path, {sidecar.PATH: waiver_file(WAIVE)})
    both = {CLAUDE: settings(allow=["Bash(curl:*)", "Bash(rm:*)"])}
    for event in ("commit", "tool_use"):
        assert keys(base, GRANT, event) == []
        assert keys(base, both, event) == ["ap-allow-broad|permissions.allow|Bash(rm:*)"]
    other_file = {".claude/settings.local.json": GRANT[CLAUDE]}
    assert len(keys(base, other_file)) == 1


def test_a_person_may_add_the_waiver_in_the_commit_an_agent_may_not(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writes = {**GRANT, sidecar.PATH: waiver_file(WAIVE)}
    for name in mod.AGENT_ENV:
        monkeypatch.delenv(name, raising=False)
    assert keys(repo, writes, "commit") == []
    assert len(keys(repo, writes, "tool_use")) == 1
    monkeypatch.setenv("CLAUDECODE", "1")
    assert len(keys(repo, writes, "commit")) == 1
    monkeypatch.setenv("CLAUDECODE", "0")
    assert keys(repo, writes, "commit") == []


def test_a_sidecar_that_breaks_the_schema_grants_nothing_and_is_reported(tmp_path: Path) -> None:
    bad = json.dumps({"waive": [WAIVE], "extra": True})
    base = held(tmp_path, {sidecar.PATH: bad})
    assert len(keys(base, GRANT)) == 1
    (found,) = mod.findings(payload(base, {sidecar.PATH: bad}))
    assert found["key"].startswith("ap-sidecar-invalid|")
    assert found["path"] == sidecar.PATH
    assert mod.findings(payload(base, {sidecar.PATH: waiver_file(WAIVE)})) == []
    unknown_entry = json.dumps({"waive": [{**WAIVE, "reason": "ok"}]})
    assert len(mod.findings(payload(base, {sidecar.PATH: unknown_entry}))) == 1


def test_non_text_writes_are_skipped(repo: Path) -> None:
    assert mod.findings({"event": "commit", "repo_root": str(repo), "writes": {CLAUDE: None}}) == []
    assert mod.findings({"event": "commit"}) == []


def test_person_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in mod.AGENT_ENV:
        monkeypatch.delenv(name, raising=False)
    assert mod.by_person("commit") and mod.by_person("push")
    assert not mod.by_person("tool_use")
    monkeypatch.setenv("AI_AGENT", "yes")
    assert not mod.by_person("commit")


# --- as a process and through the engine ---------------------------------------------------------------------


def run(repo: Path, writes: dict[str, str], event: str = "commit") -> tuple[int, str, str]:
    proc = scriptkit.run_script_full(POLICY, NAME, repo, json.dumps(payload(repo, writes, event)))
    return proc.returncode, proc.stdout, proc.stderr


def test_exit_codes_and_the_document(repo: Path) -> None:
    code, out, err = run(repo, {CLAUDE: settings(allow=["Read"])})
    assert (code, json.loads(out)) == (0, {"findings": []}) and not err
    code, out, err = run(repo, GRANT)
    assert code == 1
    assert json.loads(out)["findings"][0]["key"] == "ap-allow-broad|permissions.allow|Bash(curl:*)"
    assert "grants more than named" in err and sidecar.PATH in err and "Bash(curl:*)" in err


def test_a_fault_exits_2_and_never_reads_as_a_verdict(repo: Path) -> None:
    proc = scriptkit.run_script_full(POLICY, NAME, repo, "not json")
    assert proc.returncode == 2
    assert "could not reach a decision" in proc.stderr


def test_the_engine_warns_on_a_new_grant_and_not_on_one_already_there(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: settings(allow=["Bash(curl:*)"])})
    scriptkit.write(base, {CLAUDE: settings(allow=["Read", "Bash(curl:*)"])})
    scriptkit.git(base, "add", "-A")
    assert gatekit.judge(POLICY, base, gatekit.COMMIT)[0] == 0
    scriptkit.write(base, {CLAUDE: settings(allow=["Read", "Bash(curl:*)", "Bash(sudo:*)"])})
    scriptkit.git(base, "add", "-A")
    _, err = gatekit.judge(POLICY, base, gatekit.COMMIT)
    assert "Bash(sudo:*)" in err and "Bash(curl:*)" not in err and "warn" in err.lower()


def test_the_engine_flags_a_removed_deny_entry_at_commit_and_at_the_turns_end(tmp_path: Path) -> None:
    base = held(tmp_path, {CLAUDE: settings(deny=["Read(.env)"])})
    scriptkit.write(base, {CLAUDE: settings(allow=["Read"])})
    scriptkit.git(base, "add", "-A")
    for event in (gatekit.COMMIT, gatekit.STOP):
        _, err = gatekit.judge(POLICY, base, event, {CLAUDE: settings(allow=["Read"])})
        assert "deny entry" in err

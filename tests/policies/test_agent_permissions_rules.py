"""agent-permissions-scan: the rules, the parsers and the walker, without the gate script around them."""

from __future__ import annotations

import pytest
from policies.permskit import load, rules

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
    assert rules.broad_entry("Bash(git push --force:*)") == "a wildcard over git push"
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


@pytest.mark.parametrize(
    "pattern",
    [
        "/.*/",
        "/.+/i",
        "/^.*$/",
        "/(?:)/",
        "/\\S+/",
        "/[\\s\\S]*/",
        "//",
        "/.*?/",
        "/\\s*/",
        "/x*/",
        "/.{0,}/",
        "/[^\\n]*/",
        "/(a|)/",
        "/.*|foo/",
        "/(?=)/",
        "/^(?!x)/",
        "/./",
        "/(?<n>x)/",
        "/[/",
        "*",
        "**",
        "https://*",
        "/",
        "**/*",
    ],
)
def test_approval_rules_that_reach_everything(pattern: str) -> None:
    assert rules.approval_reach(pattern) == rules.ALL_REASON


@pytest.mark.parametrize(
    "pattern",
    ["rm", "curl -s", "/^curl\\b/", "/curl .*/", "/.*curl/", "/^(?:git|curl)/", "sudo", "/usr/bin/rm", "bash"],
)
def test_approval_rules_that_reach_a_risky_command(pattern: str) -> None:
    assert rules.approval_reach(pattern) == rules.RISKY_REASON


@pytest.mark.parametrize(
    "pattern",
    ["git status", "/^git status$/", "/^ls\\b/", "**/*.ts", "https://example.com", "src/**", "npm test", "!!!"],
)
def test_narrow_approval_rules(pattern: str) -> None:
    assert rules.approval_reach(pattern) is None


def test_a_very_long_pattern_is_judged_broad() -> None:
    assert rules.approval_reach("/" + "a" * 600 + "/") == rules.ALL_REASON


@pytest.mark.parametrize(
    "entry",
    [
        "Bash(rm -rf node_modules:*)",
        "Bash(curl -s https://api.github.com/repos:*)",
        "Bash(env NODE_ENV=test npm test:*)",
        "Bash(sudo systemctl status:*)",
        "Bash(ssh -T git@github.com:*)",
        "Bash(bash scripts/test.sh:*)",
        "Bash(git pull:*)",
    ],
)
def test_a_risky_command_with_a_real_argument_is_scoped(entry: str) -> None:
    assert rules.broad_entry(entry) is None


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
        (".continue/a/config.yml", ("yaml", "continue")),
        (".continue/config.json", ("json", "continue")),
        (".continue/permissions.yaml", ("yaml", "continue")),
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


def test_blank_and_pathologically_nested_files() -> None:
    for kind in ("json", "toml", "yaml"):
        assert load.parse(kind, " \n").tree == {}
    with pytest.raises(load.UnreadableError):
        load.parse("toml", "a = " + "[" * 6000 + "]" * 6000)


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

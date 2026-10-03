"""protect-agent-config 0.3.2: here-documents, mkdir of a plugin root, CLAUDE.local.md, `$'..'` and variables as `--plugin-dir`."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest
from policies import guardkit

POLICY = "protect-agent-config"
guard = guardkit.load_guard(POLICY)
gate_script = guardkit.load_guard(POLICY, "protect-agent-config-gate")
pathset = guardkit.load_guard(POLICY, "pathset")
plugin = guardkit.load_guard(POLICY, "pathplugin")
load = guardkit.load_guard(POLICY, "pathload")

ASSIGNMENTS = [
    "set CLAUDE_CODE_PLUGIN_DIRS=x",
    "setx CLAUDE_CODE_PLUGIN_DIRS x",
    '$env:CLAUDE_CODE_PLUGIN_DIRS = "x"',
    "Set-Item Env:CLAUDE_CODE_PLUGIN_DIRS x",
    "[Environment]::SetEnvironmentVariable('CLAUDE_CODE_PLUGIN_DIRS', 'x', 'User')",
]
QUOTED = [
    "cat > notes.md <<'EOF'\n{line}\nEOF",
    'git commit -m "docs\n\n{line}"',
    'echo "intro\n{line}"',
    "cat <<EOF\ntext\n{line}\nEOF",
]


@pytest.fixture(autouse=True)
def _repo_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    for name in (".git", "src", "docs", "plug/hooks", "plug/.claude-plugin"):
        (root / name).mkdir(parents=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return root


@pytest.mark.parametrize("line", ASSIGNMENTS)
@pytest.mark.parametrize("shape", QUOTED)
def test_text_that_only_quotes_a_windows_assignment_is_not_one(shape: str, line: str) -> None:
    raw = shape.format(line=line)
    assert guard.check(raw) is None, raw
    assert not load.loads_plugin(raw)


@pytest.mark.parametrize("line", ASSIGNMENTS)
@pytest.mark.parametrize(
    "shape",
    [
        "{line}",
        "echo hi\n{line}",
        "echo hi && {line}",
        "echo hi; {line}",
        "sudo {line}",
        "cmd /c {quoted}",
        "bash -c {quoted}",
        "pwsh -Command {quoted}",
        "if ($true) {{ {line} }}",
        "if ($true) {{{line}}}",
    ],
)
def test_a_windows_assignment_where_a_command_starts_is_still_refused(shape: str, line: str) -> None:
    raw = shape.format(line=line, quoted=shlex.quote(line))
    assert load.loads_plugin(raw), raw
    assert guard.check(raw) is not None, raw


@pytest.mark.parametrize(
    "raw",
    [
        "@set CLAUDE_CODE_PLUGIN_DIRS=x",
        "$null = [Environment]::SetEnvironmentVariable('CLAUDE_CODE_PLUGIN_DIRS', 'x')",
        '[void][System.Environment]::SetEnvironmentVariable("CLAUDE_CODE_PLUGIN_DIRS", "x")',
        "$env:CLAUDE_CODE_PLUGIN_DIRS += ';more'",
        "SET claude_code_plugin_dirs=x",
        '$env:CLAUDE_CODE_PLUGIN_DIRS="/a/b"',
    ],
)
def test_the_other_spellings_of_a_windows_assignment_are_refused(raw: str) -> None:
    assert guard.check(raw) == guard.LOADS, raw


def test_a_command_the_quotes_do_not_balance_for_is_read_split_at_every_separator() -> None:
    assert guard.check('echo "unbalanced; set CLAUDE_CODE_PLUGIN_DIRS=x') == guard.LOADS
    assert guard.check('echo "unbalanced set CLAUDE_CODE_PLUGIN_DIRS=x') is None


def test_a_redirection_alone_and_a_bare_assignment_are_not_commands_to_read() -> None:
    assert guard.check("> out.txt") is None
    assert guard.check("A=1") is None
    assert not load._foreign("A=1 B=2")


def test_a_script_inside_a_script_is_read_only_a_few_levels_deep() -> None:
    script = "setx CLAUDE_CODE_PLUGIN_DIRS x"
    nested = [script]
    for _ in range(6):
        nested.append(f"bash -c {shlex.quote(nested[-1])}")
    assert load._foreign(nested[2])
    assert not load._foreign(nested[-1])


def test_a_variable_holding_the_flag_is_read_as_the_flag() -> None:
    for raw in (
        "A=--plugin-dir; claude $A x",
        "A=--plugin-dir; claude ${A} x",
        'A=--plugin-dir; claude "$A" x',
        'A="--plugin-dir x"; claude $A',
        "A=--plugin-dir=x; claude $A",
        "A=--plugin-dir; B=$A; claude $B x",
        "A=--plugin-dir; sudo claude $A x",
        "export A=--plugin-dir; claude $A x",
        "A=--plugin-dir; npx @anthropic-ai/claude-code $A x",
        "A=--plugin-dir; bash -c 'claude $A x'",
    ):
        assert guard.check(raw) == guard.LOADS, raw


@pytest.mark.parametrize(
    "raw",
    [
        "A=--other; claude $A x",
        "claude $A x",
        "A=--plugin-dir; mytool $A x",
        "A=--plugin-dir; echo $A x",
        'A=--plugin-dir; claude -p "say $A"',
        'claude -p "explain --plugin-dir"',
        'claude -p "see $HOME --plugin-dir"',
        "claude $'--print' x",
        "echo $'--plugin-dir'",
    ],
)
def test_a_variable_or_quoted_word_that_is_not_the_flag_passes(raw: str) -> None:
    assert guard.check(raw) is None, raw


@pytest.mark.parametrize(
    "raw",
    [
        "claude $'--plugin-dir' x",
        "claude $'--plugin-dir=x'",
        "claude $'\\x2d\\x2dplugin-dir' x",
        "$'claude' $'--plugin-dir' x",
        "CLAUDE_CODE_PLUGIN_DIRS=x claude",
    ],
)
def test_ansi_c_quoting_is_decoded_in_the_plugin_check(raw: str) -> None:
    assert guard.check(raw) == guard.LOADS, raw


MKDIR = [
    "mkdir -p plug2/.claude-plugin plug2/hooks; echo x > plug2/hooks/h.json",
    "mkdir plug2/.CLAUDE-PLUGIN",
    "mkdir -p plug2/.claude-plugin",
    "mkdir .claude-plugin",
    "mkdir -p a/b/.Claude-Plugin/c",
    "mkdir -p plug2/.claude-plugin/",
    "mkdir -m 755 plug2/.claude-plugin",
    "mkdir -p plug2/{.claude-plugin,hooks}",
    'mkdir -p "plug2/.claude-plugin"',
    "mkdir plug2\\.claude-plugin",
    "md plug2\\.claude-plugin",
    "md plug2/.claude-plugin",
    "cd plug2 && mkdir .claude-plugin",
    "D=plug2; mkdir -p $D/.claude-plugin",
    "mkdir -p $(echo plug2)/.claude-plugin",
    "bash -c 'mkdir -p plug2/.claude-plugin'",
    "install -d plug2/.claude-plugin",
    "New-Item -ItemType Directory -Path plug2/.claude-plugin",
]
MKDIR_OPEN = [
    "mkdir -p src/hooks",
    "mkdir -p src/.claude-plugins",
    "mkdir -p docs/claude-plugin",
    "mkdir .kiro",
    "mkdir -p .clinerules/hooks",
    "mkdir -p build/out",
    "mkdir plug2",
    "mkdir -p plug2/hooks",
    "ls plug/.claude-plugin",
]


@pytest.mark.parametrize("raw", MKDIR)
def test_making_a_plugins_manifest_folder_is_refused(raw: str) -> None:
    assert guard.check(raw) == guard.REASON, raw


@pytest.mark.parametrize("raw", MKDIR_OPEN)
def test_making_any_other_folder_stays_open(raw: str) -> None:
    assert guard.check(raw) is None, raw


def test_the_plugin_root_made_in_the_same_command_is_refused_before_its_hooks_are_written() -> None:
    assert guard.check("mkdir -p plug2/hooks && echo x > plug2/hooks/h.json") is None
    assert guard.check("mkdir -p plug2/.claude-plugin plug2/hooks && echo x > plug2/hooks/h.json") == guard.REASON


INSTRUCTION_FILES = ["CLAUDE.local.md", "sub/CLAUDE.local.md", "~/CLAUDE.local.md", ".CLAUDE.LOCAL.MD"]


@pytest.mark.parametrize("path", INSTRUCTION_FILES)
def test_a_personal_claude_instruction_file_is_protected_like_claude_md(_repo_root: Path, path: str) -> None:
    assert guard.check(f"echo x > {path}") == guard.REASON
    assert gate_script.judge(_repo_root, path) == "block"
    assert pathset.verdict(path) == pathset.BLOCK


def test_a_personal_claude_instruction_file_below_docs_asks_a_person(_repo_root: Path) -> None:
    assert guard.check("echo x > docs/CLAUDE.local.md") == guard.ASK
    assert gate_script.judge(_repo_root, "docs/CLAUDE.local.md") == "ask"
    assert guard.check("echo x > CLAUDE.local.md.txt") is not None
    assert guard.check("echo x > src/claude.local.txt") is None

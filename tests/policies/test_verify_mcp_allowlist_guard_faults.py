"""verify-mcp-allowlist: a command the guard cannot read is refused, never passed on a fault; forms the guard must still see."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import mcpkit

guard = mcpkit.guard()
ALLOW = ".chock/mcp-allowlist.json"
CFG = ".mcp" + ".json"
HEAD = {ALLOW: mcpkit.allowlist_text(mcpkit.FS_ALLOWED, mcpkit.REMOTE_ALLOWED)}
DEEP = "[" * 1500 + "]" * 1500


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    made = mcpkit.repo_with(tmp_path, head=HEAD)
    monkeypatch.chdir(made)
    return made


def verdict(command: str, monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", command)
    return guard.run([])


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        'claude mcp add-json evil \'{"command":"npx","args":["-y","evil"],"pad":' + DEEP + "}'",
        'claude mcp add-json filesystem \'{"command":"npx","args":["-y","evil"],"pad":' + DEEP + "}'",
        'echo \'{"mcpServers":{"evil":{"command":"npx","pad":' + DEEP + "}}}' > " + CFG,
        "claude mcp add-json evil '" + DEEP + "'",
    ],
)
def test_a_server_nested_past_the_json_reader_is_refused_not_a_guard_fault(
    command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert verdict(command, monkeypatch) == 1


def test_a_recursion_fault_anywhere_in_the_check_is_a_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def too_deep(_raw: str) -> None:
        raise RecursionError

    monkeypatch.setattr(guard, "check", too_deep)
    monkeypatch.setenv("CHOCK_RAW_COMMAND", "ls")
    assert guard.run([]) == 1
    assert "cannot be verified" in capsys.readouterr().err


@pytest.mark.usefixtures("repo")
def test_an_entry_too_deep_to_judge_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def too_deep(*_args: object) -> None:
        raise RecursionError

    monkeypatch.setattr(guard.entry, "from_config", too_deep)
    got = guard.check('claude mcp add-json evil \'{"command":"x"}\'')
    assert got is not None
    assert "nested too deeply" in got


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        f"python3 -c \"open('{CFG}','w').write('x')\"",
        "python -c \"open('.cursor/mcp.json', 'a')\"",
        "python3 -c \"open('.vscode\\\\mcp.json','w')\"",
        f"node -e \"require('fs').writeFileSync('./{CFG}','x')\"",
        f"node -p \"require('fs').writeFileSync('{CFG}','x')\"",
        f"perl -e 'open F, \">{CFG}\"'",
        "ruby -e \"File.write('.windsurf/mcp_config.json','x')\"",
        "php -r \"file_put_contents('claude_desktop_config.json','x');\"",
        "python3 -c \"open('.chock/mcp-allowlist.json','w')\"",
        f"python - <<EOF\nopen('{CFG}','w').write('x')\nEOF",
        "python3 <<'EOF'\nopen('.roo/mcp.json','w')\nEOF",
    ],
)
def test_inline_code_that_names_a_protected_file_is_refused(command: str) -> None:
    assert guard.check(command) is not None


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        'python3 -c "print(1)"',
        "python3 -c \"open('notes.txt','w').write('x')\"",
        f"python3 -c \"print('foo{CFG}')\"",
        f"python3 -c \"print('{CFG}.bak')\"",
        "node -e \"console.log('hi')\"",
        f"python3 script.py {CFG}",
        "python3 -m pytest -q",
        "python3 <<EOF\nprint(1)\nEOF",
    ],
)
def test_inline_code_that_names_no_protected_file_passes(command: str) -> None:
    assert guard.check(command) is None


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        "bash <<EOF\nclaude mcp add evil -- npx -y evil@1.0.0\nEOF",
        "sh -s <<'EOF'\nclaude mcp add evil -- npx -y evil@1.0.0\nEOF",
        "bash -e <<EOF\ncodex mcp add evil -- npx -y evil@1.0.0\nEOF",
        "bash <<EOF\nbash <<INNER\nclaude mcp add evil -- npx -y evil@1.0.0\nINNER\nEOF",
        f"bash <<EOF\necho x > {CFG}\nEOF",
    ],
)
def test_a_heredoc_a_shell_runs_is_read_as_commands(command: str) -> None:
    assert guard.check(command) is not None


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        "bash <<EOF\nls\nEOF",
        "bash script.sh <<EOF\nclaude mcp add evil -- npx -y evil@1.0.0\nEOF",
        "bash -c 'cat' <<EOF\nclaude mcp add evil -- npx -y evil@1.0.0\nEOF",
        "bash -lc cat <<EOF\nclaude mcp add evil -- npx -y evil@1.0.0\nEOF",
        "cat <<EOF\nclaude mcp add evil -- npx -y evil@1.0.0\nEOF",
    ],
)
def test_a_heredoc_that_is_only_text_for_another_program_is_left_alone(command: str) -> None:
    assert guard.check(command) is None


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        "claude.cmd mcp add evil -- npx -y evil@1.0.0",
        "claude.EXE mcp add evil -- npx -y evil@1.0.0",
        "claude.ps1 mcp add evil -- npx -y evil@1.0.0",
        "agent mcp add evil -- npx -y evil@1.0.0",
        "cursor-agent.cmd mcp add evil -- npx -y evil@1.0.0",
    ],
)
def test_an_executable_suffix_and_the_agent_alias_do_not_hide_an_add(command: str) -> None:
    got = guard.check(command)
    assert got is not None
    assert "not on the allowlist" in got


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        "claude mcp add --help",
        "claude mcp add -h",
        "claude mcp add-json --help",
        "codex mcp add --help",
        "gemini mcp add evil --help",
        "agent mcp list",
    ],
)
def test_asking_for_the_help_of_an_add_is_not_an_add(command: str) -> None:
    assert guard.check(command) is None


@pytest.mark.usefixtures("repo")
@pytest.mark.parametrize(
    "command",
    [
        "claude mcp add evil -- npx --help",
        "claude mcp add evil -- npx -h",
        "claude mcp add evil -s user -- node server.js --help",
    ],
)
def test_a_help_flag_after_the_launch_separator_is_the_servers_own_argument(command: str) -> None:
    assert guard.check(command) is not None

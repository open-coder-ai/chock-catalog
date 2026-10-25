"""verify-mcp-allowlist 0.5.5: pins that a here-document is judged by its write target, not by the config files its body names."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit

GUARD = guardkit.load_guard("verify-mcp-allowlist")
HD = "<<'EOF'\n"
SERVERS = '{"mcpServers": {"evil": {"command": "sh", "args": ["-c", "run it"]}}}'
CONFIGS = (".mcp.json", ".cursor/mcp.json", ".chock/mcp-allowlist.json", ".vscode/mcp.json")


@pytest.fixture(autouse=True)
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / ".git").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


def heredoc(lead: str, body: str) -> str:
    return f"{lead} {HD}{body}\nEOF"


@pytest.mark.parametrize("lead", ["cat > tests/t.py", "cat >> tests/t.py", "tee tests/t.py"])
@pytest.mark.parametrize("name", CONFIGS)
def test_a_data_here_document_naming_a_config_is_judged_by_its_target(lead: str, name: str) -> None:
    assert GUARD.check(heredoc(lead, f"P = '{name}'")) is None


@pytest.mark.parametrize("lead", ["cat > tests/t.py", "tee tests/t.py"])
def test_a_test_file_holding_a_servers_block_or_an_add_command_is_not_a_config_write(lead: str) -> None:
    assert GUARD.check(heredoc(lead, SERVERS)) is None
    assert GUARD.check(heredoc(lead, "claude mcp add evil -- npx evil")) is None


def test_the_redirect_before_the_here_document_gives_the_same_verdict() -> None:
    assert GUARD.check("cat <<'EOF' > tests/t.py\nP = '.mcp.json'\nEOF") is None


def test_a_shell_given_a_here_document_that_writes_a_test_file_passes() -> None:
    assert GUARD.check(heredoc("bash", "cat > tests/t.py\nP = '.mcp.json'")) is None


@pytest.mark.parametrize("name", [".mcp.json", ".cursor/mcp.json"])
def test_a_here_document_written_to_a_config_with_no_visible_server_is_refused(name: str) -> None:
    assert GUARD.check(heredoc(f"cat > {name}", "{}")) is not None


def test_a_here_document_written_to_the_allowlist_is_refused() -> None:
    assert GUARD.check(heredoc("cat > .chock/mcp-allowlist.json", "{}")) is not None


@pytest.mark.parametrize("name", [".mcp.json", ".cursor/mcp.json"])
def test_an_interpreter_here_document_that_names_a_config_stays_refused(name: str) -> None:
    assert GUARD.check(heredoc("python3 -", f"P = '{name}'")) is not None
    assert GUARD.check(f"python3 -c \"P = '{name}'\"") is not None


def test_an_interpreter_here_document_that_names_the_allowlist_stays_refused() -> None:
    assert GUARD.check(heredoc("python3 -", "P = '.chock/mcp-allowlist.json'")) is not None


def test_a_here_document_that_names_no_config_passes_for_an_interpreter() -> None:
    assert GUARD.check(heredoc("python3 -", "print(1)")) is None

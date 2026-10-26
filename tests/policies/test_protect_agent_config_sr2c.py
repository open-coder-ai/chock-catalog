"""protect-agent-config 0.7.5: pins that a here-document is judged by its target, that implementations/ is protected where hooks run, and that reads pass."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit

GUARD = guardkit.load_guard("protect-agent-config")
GATE = guardkit.load_guard("protect-agent-config", "protect-agent-config-gate")
HD = "<<'EOF'\n"
SOURCES = ("base/some-policy/implementations", "agentic-security/some-policy/implementations")
INSTALLED = ".agents/policies/some-policy/implementations"


@pytest.fixture(autouse=True)
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / ".git").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)
    return tmp_path


def refused(command: str) -> bool:
    return GUARD.check(command) is not None


def heredoc(lead: str, body: str) -> str:
    return f"{lead} {HD}{body}\nEOF"


NAMES = (
    ".chock/dependency-allowlist.txt",
    ".chock/compiled/some-policy/gate.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".claude/settings.json",
    f"{INSTALLED}/guard.py",
)


@pytest.mark.parametrize(
    "lead", ["cat > tests/policies/test_x.py", "cat >> tests/policies/test_x.py", "tee tests/test_x.py"]
)
@pytest.mark.parametrize("name", NAMES)
def test_a_data_here_document_is_judged_by_its_target_not_its_body(lead: str, name: str) -> None:
    assert not refused(heredoc(lead, f"PATH = '{name}'"))


@pytest.mark.parametrize(
    "target", [".mcp.json", ".chock/compiled/some-policy/gate.json", f"{INSTALLED}/guard.py", "AGENTS.md"]
)
def test_a_here_document_written_to_a_protected_target_is_refused(target: str) -> None:
    assert refused(heredoc(f"cat > {target}", "x"))
    assert refused(heredoc(f"tee {target}", "x"))


@pytest.mark.parametrize("name", NAMES)
def test_an_interpreter_here_document_that_names_a_protected_path_stays_refused(name: str) -> None:
    assert refused(heredoc("python3 -", f"print('{name}')"))


@pytest.mark.parametrize("name", NAMES[:5])
def test_a_script_written_and_run_in_one_command_that_names_a_protected_path_stays_refused(name: str) -> None:
    assert refused(f"cat > probe.py {HD}P = '{name}'\nEOF\npython3 probe.py")


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize(
    "template",
    [
        "echo x > {p}/guard.py",
        "sed -i 's/a/b/' {p}/guard.py",
        "tee {p}/guard.py <<'EOF'\nx\nEOF",
        "cat > {p}/guard.py <<'EOF'\nx\nEOF",
        "cp new.py {p}/guard.py",
        "mv new.py {p}/guard.py",
    ],
)
def test_a_catalog_source_implementations_folder_is_not_protected(source: str, template: str) -> None:
    assert not refused(template.format(p=source))


@pytest.mark.parametrize(
    "template",
    [
        "echo x > {p}/guard.py",
        "sed -i 's/a/b/' {p}/guard.py",
        "tee {p}/guard.py <<'EOF'\nx\nEOF",
        "cp new.py {p}/guard.py",
        "rm {p}/guard.py",
        "echo x > .chock/compiled/some-policy/gate.json",
    ],
)
def test_an_installed_copy_and_the_compiled_folder_are_protected(template: str) -> None:
    assert refused(template.format(p=INSTALLED))


def test_a_link_from_a_source_folder_to_the_installed_copy_is_followed(repo: Path) -> None:
    (repo / ".agents" / "policies" / "some-policy" / "implementations").mkdir(parents=True)
    (repo / "base" / "some-policy").mkdir(parents=True)
    (repo / "base" / "some-policy" / "implementations").symlink_to(repo / INSTALLED, target_is_directory=True)
    assert refused("echo x > base/some-policy/implementations/guard.py")


@pytest.mark.parametrize(
    "command",
    [
        "ls .chock/compiled",
        "ls -la .chock/compiled/some-policy/",
        "cat .chock/compiled/some-policy/stop/gate.json",
        "cat .chock/compiled/some-policy/gate.json | head -20",
        "head -5 .chock/compiled/some-policy/gate.json",
        "tail -5 .chock/compiled/some-policy/gate.json",
        "wc -l .chock/compiled/*/stop/gate.json",
        "grep -rn foo .chock/compiled | head",
        "find .chock/compiled -name '*.json'",
        "find .chock/compiled -name '*.json' -exec cat {} +",
        "diff -r .chock/compiled/some-policy base/some-policy",
        "jq . .chock/compiled/some-policy/gate.json",
        "cat .chock/compiled/some-policy/gate.json > out.txt",
        "cp .chock/compiled/some-policy/gate.json tmp/gate.json",
        "git diff .chock/compiled",
        "git show HEAD:.chock/compiled/some-policy/gate.json",
        "git log -p -- .chock/compiled",
        "cat .agents/policies/some-policy/implementations/guard.py",
        "ls .agents/policies/some-policy/implementations",
        "diff .agents/policies/some-policy/implementations/guard.py base/some-policy/implementations/guard.py",
    ],
)
def test_reads_of_the_compiled_folder_and_installed_copies_pass(command: str) -> None:
    assert not refused(command)


@pytest.mark.parametrize("path", [f"{source}/guard.py" for source in SOURCES])
def test_the_edit_gate_leaves_catalog_sources_open(repo: Path, path: str) -> None:
    assert GATE.judge(repo, path) == ""


@pytest.mark.parametrize("path", [f"{INSTALLED}/guard.py", ".chock/compiled/some-policy/gate.json"])
def test_the_edit_gate_refuses_installed_copies_and_compiled_files(repo: Path, path: str) -> None:
    assert GATE.judge(repo, path) == "block"

"""block-no-verify 0.5.1 and protect-agent-config 0.7.3: the launcher interpreter key, core.hooksPath removal, direct repository-config writes."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import guardkit

BLOCK, ASK, OK = 1, 3, 0
NO_VERIFY = guardkit.load_guard("block-no-verify")
PROTECT = guardkit.load_guard("protect-agent-config")
PATHSET = guardkit.load_guard("protect-agent-config", "pathset")

ROWS: list[tuple[str, int]] = [
    ("git config chock.python /bin/true", BLOCK),
    ("git config --local chock.python /bin/true", BLOCK),
    ("git config --global CHOCK.PYTHON /bin/true", BLOCK),
    ("git config --add chock.python /bin/true", BLOCK),
    ("git -c chock.python=/bin/true commit -m x", BLOCK),
    ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=chock.python GIT_CONFIG_VALUE_0=/bin/true git commit -m x", BLOCK),
    ("git config --unset core.hooksPath", BLOCK),
    ("git config --unset-all core.hooksPath", BLOCK),
    ("git config unset core.hooksPath", BLOCK),
    ("git config --file .git/config user.name x", BLOCK),
    ("git config -f .git/config user.name x", BLOCK),
    ("git config --file=.git/config a.b c", BLOCK),
    ("git config -f.git/config a.b c", BLOCK),
    ("git config --remove-section core", ASK),
    ("git config chock.python", OK),
    ("git config --get chock.python", OK),
    ("git config --unset chock.python", OK),
    ("git config --file .git/config user.name", OK),
    ("git config --file .git/config --list", OK),
    ("git config --file .gitmodules a.b c", OK),
    ("git config user.name x", OK),
]


@pytest.mark.parametrize(("raw", "code"), ROWS)
def test_block_no_verify_judges_the_launcher_key_and_repository_config(
    raw: str, code: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CHOCK_RAW_COMMAND", raw)
    assert NO_VERIFY.run([]) == code, raw


@pytest.fixture
def _repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (".git", ".chock", "src"):
        (tmp_path / name).mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CHOCK_HOOK_CWD", raising=False)


@pytest.mark.usefixtures("_repo")
@pytest.mark.parametrize(
    "raw",
    [
        "git config chock.python /bin/true",
        "git config --global chock.python /bin/true",
        "git -c chock.python=x status",
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=chock.python GIT_CONFIG_VALUE_0=x git status",
        "echo x >> .chock/config.yaml",
        "sed -i s/a/b/ .chock/config.yaml",
        "rm .chock/config.yaml",
        "echo x >> .git/config",
        "sh -c 'echo x >> .chock/config.yaml'",
        'bash -c "echo x > .chock/config.yaml"',
        "eval 'echo x >> .chock/config.yaml'",
        "eval 'echo x > .chock/guardrails.json'",
    ],
)
def test_protect_agent_config_refuses_the_shell_routes(raw: str) -> None:
    assert PROTECT.check(raw) is not None, raw


@pytest.mark.usefixtures("_repo")
@pytest.mark.parametrize(
    "raw",
    ["git config --get chock.python", "git config chock.python", "cat .chock/config.yaml", "git config user.name x"],
)
def test_protect_agent_config_allows_reads_and_ordinary_keys(raw: str) -> None:
    assert PROTECT.check(raw) is None, raw


@pytest.mark.parametrize("path", [".chock/config.yaml", "sub/.chock/config.yaml", ".CHOCK/Config.yaml", ".git/config"])
def test_the_edit_write_gate_protects_the_chock_config_and_repository_config(path: str) -> None:
    assert PATHSET.verdict(path) == PATHSET.BLOCK, path

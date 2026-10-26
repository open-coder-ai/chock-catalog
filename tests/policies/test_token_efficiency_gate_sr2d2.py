"""token-efficiency-gate: a command is compared with the session log as the log stores it, secrets redacted."""

from __future__ import annotations

from pathlib import Path

import pytest
from policies import scriptkit, toolcallkit
from policies.toolcallkit import payload, record, write_log

mod = scriptkit.load("token-efficiency", "token-efficiency-gate.py")
# The value is a variable reference: the log's redaction takes it, scan-secrets does not.
CMD = 'tool --password="$NOT_A_SECRET_VARIABLE" --verbose'
STORED = "tool --[redacted] --verbose"


def failures(command: str, n: int = 3) -> list[dict]:
    return [record("Bash", "post", "error", call=f"b{i}", command=command) for i in range(n)]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return toolcallkit.make_repo(tmp_path)


def run(repo: Path, monkeypatch, capsys, records: list[dict], command: str = CMD) -> tuple[int, str]:
    write_log(repo, records)
    return toolcallkit.fire(mod, monkeypatch, capsys, payload(repo, "Bash", {"command": command}))


def test_the_stored_form_redacts_a_secret_after_masking_assignments() -> None:
    assert mod.logged_command(CMD) == STORED
    assert mod.logged_command("LEVEL=3 " + CMD) == "LEVEL=*** " + STORED
    assert mod.logged_command("make test") == "make test"


def test_a_command_holding_a_redacted_secret_matches_its_stored_form(repo, monkeypatch, capsys) -> None:
    code, err = run(repo, monkeypatch, capsys, failures(STORED))
    assert code == 4
    assert "retry cap 3" in err


def test_a_log_that_kept_the_command_unredacted_still_matches(repo, monkeypatch, capsys) -> None:
    assert run(repo, monkeypatch, capsys, failures(CMD))[0] == 4


def test_another_command_or_too_few_failures_stay_quiet(repo, monkeypatch, capsys) -> None:
    assert run(repo, monkeypatch, capsys, failures(STORED, 2)) == (0, "")
    assert run(repo, monkeypatch, capsys, failures("tool --[redacted] --quiet")) == (0, "")

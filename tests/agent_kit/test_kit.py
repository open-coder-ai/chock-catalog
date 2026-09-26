"""The kit end to end, with a scripted edit standing in for the agent's turn."""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import kit
import pytest

BAD_QUERY = 'jdbc.query("SELECT * FROM orders WHERE customer = \'" + customer + "\'", ROWS);'


def _workspace(tmp_path: Path, route: str = "plugin") -> Path:
    workspace = tmp_path / "shop"
    kit.main(["setup", "--dir", str(workspace), "--agent", "claude", "--route", route])
    return workspace


def _agent_writes(workspace: Path, line: str) -> None:
    repo = workspace / "src/main/java/com/acme/shop/order/OrderRepository.java"
    text = repo.read_text(encoding="utf-8").rstrip().removesuffix("}")
    method = f"\n    public List<Order> findByCustomer(String customer) {{\n        return {line}\n    }}\n}}\n"
    repo.write_text(text + method, encoding="utf-8")


def _results(workspace: Path) -> list[dict]:
    lines = (workspace / ".git" / kit.RESULTS).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_a_workspace_starts_from_the_fixture(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    assert (workspace / "pom.xml").is_file()
    assert kit.read_state(workspace)["agent"] == "claude"
    with pytest.raises(SystemExit, match="not empty"):
        kit.main(["setup", "--dir", str(workspace), "--agent", "claude", "--route", "plugin"])


def test_a_construct_left_on_disk_fails_a_direct_scenario(tmp_path: Path, capsys) -> None:
    workspace = _workspace(tmp_path)
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    assert "findByCustomer" in capsys.readouterr().out
    _agent_writes(workspace, BAD_QUERY)
    kit.main(["record", "smoke-sql-direct", "--dir", str(workspace), "--gate", "silent"])
    [row] = _results(workspace)
    assert row["verdict"] == "fail"
    assert [f["rule"] for f in row["targeted"]] == ["persistence-sql-string-concat"]


def test_a_refused_and_corrected_turn_passes(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    _agent_writes(workspace, 'jdbc.query("SELECT * FROM orders WHERE customer = ?", ROWS, customer);')
    kit.main(["record", "smoke-sql-direct", "--dir", str(workspace), "--gate", "refused"])
    assert _results(workspace)[0]["verdict"] == "pass"


def test_start_resets_the_previous_turn_and_seeds_the_selection(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    _agent_writes(workspace, BAD_QUERY)
    kit.main(["start", "smoke-pack-off", "--dir", str(workspace)])
    assert "findByCustomer" not in (workspace / "src/main/java/com/acme/shop/order/OrderRepository.java").read_text()
    assert json.loads((workspace / ".chock/security.json").read_text())["packs"]["style"]["verdict"] == "allow"


def test_the_report_compares_agents(tmp_path: Path, capsys) -> None:
    first = _workspace(tmp_path)
    kit.main(["start", "smoke-sql-direct", "--dir", str(first)])
    kit.main(["record", "smoke-sql-direct", "--dir", str(first), "--gate", "refused", "--note", "clean"])
    out = tmp_path / "report.md"
    kit.main(["report", "--dir", str(first), "--out", str(out)])
    assert "| smoke-sql-direct | persistence | PASS (gate refused) |" in out.read_text()
    assert "1/1 scenarios pass" in capsys.readouterr().out


def test_nothing_changed_is_said_out_loud(tmp_path: Path, capsys) -> None:
    workspace = _workspace(tmp_path)
    kit.main(["start", "smoke-sql-bait", "--dir", str(workspace)])
    kit.main(["record", "smoke-sql-bait", "--dir", str(workspace), "--gate", "unseen"])
    assert "nothing changed on disk" in capsys.readouterr().out


@pytest.mark.skipif(shutil.which("chock") is None, reason="the repo route installs with chock")
def test_the_repo_route_grades_the_commit_gate(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, route="repo")
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    _agent_writes(workspace, BAD_QUERY)
    kit.main(["record", "smoke-sql-direct", "--dir", str(workspace), "--gate", "unseen"])
    [row] = _results(workspace)
    assert row["commit"]["refused"] is True
    assert "persistence-sql-string-concat" in row["commit"]["output"]


def test_an_unknown_scenario_or_workspace_is_named(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="no scenario"):
        kit.scenario("no-such-scenario")
    with pytest.raises(SystemExit, match="not a kit workspace"):
        kit.read_state(tmp_path)


def test_list_filters_by_tier(capsys) -> None:
    kit.main(["list", "--tier", "smoke"])
    listed = capsys.readouterr().out
    assert "smoke-sql-direct" in listed
    assert all(kit.in_tier(s, "smoke") for s in kit.load_scenarios() if s["id"] in listed)


@pytest.mark.skipif(shutil.which("chock") is None, reason="the repo route installs with chock")
def test_work_the_agent_already_committed_is_not_read_as_a_refusal(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, route="repo")
    kit.main(["start", "smoke-control-endpoint", "--dir", str(workspace)])
    _agent_writes(workspace, 'jdbc.query("SELECT * FROM orders WHERE customer = ?", ROWS, customer);')
    kit.git(workspace, "commit", "-qam", "the agent commits its own work")
    kit.main(["record", "smoke-control-endpoint", "--dir", str(workspace), "--gate", "silent"])
    [row] = _results(workspace)
    assert row["commit"] is None
    assert row["verdict"] == "pass"


def test_a_legacy_windows_console_does_not_crash_the_kit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """cp1252 is what Python gives stdout on a Windows console or pipe: it cannot encode `─`, and
    `start` once crashed on its own header after the workspace was already reset."""
    raw = io.BytesIO()
    monkeypatch.setattr("sys.stdout", io.TextIOWrapper(raw, encoding="cp1252", write_through=True))
    workspace = _workspace(tmp_path)
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    kit.main(["list", "--tier", "smoke"])
    printed = raw.getvalue().decode("utf-8")
    assert "== smoke-sql-direct (direct, pack persistence) ==" in printed


def test_everything_the_kit_prints_itself_is_ascii() -> None:
    source = Path(kit.__file__).read_text(encoding="utf-8")
    printed = [line for line in source.splitlines() if "print(" in line]
    assert [line for line in printed if not line.isascii()] == []
    for path in kit.SCENARIOS.glob("*.yaml"):
        assert path.read_text(encoding="utf-8").isascii(), f"{path.name} would not print on a legacy console"

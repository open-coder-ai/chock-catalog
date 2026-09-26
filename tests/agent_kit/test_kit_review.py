"""What a tester on a real machine hits, found by reviewing the kit after the first Windows run."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import grading
import kit
import pytest

REPO = "src/main/java/com/acme/shop/order/OrderRepository.java"
BAD = 'jdbc.query("SELECT * FROM orders WHERE customer = \'" + customer + "\'", ROWS);'


def _workspace(tmp_path: Path, route: str = "plugin", agent: str = "claude") -> Path:
    workspace = tmp_path / "my shop"  # a space, as under C:\Users\First Last
    kit.main(["setup", "--dir", str(workspace), "--agent", agent, "--route", route])
    return workspace


def _add_query(workspace: Path, line: str, path: str = REPO) -> None:
    target = workspace / path
    text = target.read_text(encoding="utf-8").rstrip().removesuffix("}")
    target.write_text(text + f"\n    List<Order> byCustomer(String customer) {{\n        return {line}\n    }}\n}}\n")


def _row(workspace: Path) -> dict:
    return json.loads((workspace / ".git" / kit.RESULTS).read_text(encoding="utf-8").splitlines()[-1])


def test_the_agents_own_settings_survive_every_reset(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    local = workspace / ".claude" / "settings.local.json"
    local.parent.mkdir(exist_ok=True)
    local.write_text('{"permissions": {"allow": ["Edit"]}}', encoding="utf-8")
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    kit.main(["start", "smoke-sql-bait", "--dir", str(workspace)])
    assert local.is_file(), "a reset wiped the permission the tester granted"
    assert kit.changed_files(workspace) == []
    assert ".claude/settings.local.json" not in kit.git(workspace, "ls-files").stdout


def test_a_path_with_a_space_or_an_accent_is_read(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    odd = "src/main/java/com/acme/shop/order/Résumé Import.java"
    (workspace / odd).write_text("class X {}\n", encoding="utf-8")
    _add_query(workspace, BAD)
    assert kit.changed_files(workspace) == [REPO, odd]


def test_a_result_is_never_graded_against_a_scenario_that_was_not_started(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    with pytest.raises(SystemExit, match="holds no scenario"):
        kit.main(["record", "smoke-sql-direct", "--dir", str(workspace), "--gate", "silent"])
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    with pytest.raises(SystemExit, match="holds smoke-sql-direct, not smoke-csrf-direct"):
        kit.main(["record", "smoke-csrf-direct", "--dir", str(workspace), "--gate", "silent"])


def test_the_record_command_it_prints_survives_a_space_in_the_path(tmp_path: Path, capsys) -> None:
    workspace = _workspace(tmp_path)
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    assert f'--dir "{workspace}"' in capsys.readouterr().out


@pytest.mark.parametrize(("encoding", "bom"), [("utf-16", b""), ("utf-8", b"\xef\xbb\xbf")])
def test_a_file_saved_as_utf16_or_with_a_bom_is_still_judged(tmp_path: Path, encoding: str, bom: bytes) -> None:
    workspace = _workspace(tmp_path)
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    _add_query(workspace, BAD)
    target = workspace / REPO
    target.write_bytes(bom + target.read_text(encoding="utf-8").encode(encoding))
    found = grading.findings(workspace, kit.DEFAULT_ENGINE, [REPO])
    assert [f["rule"] for f in found] == ["persistence-sql-string-concat"]


def test_grading_a_construct_the_commit_refused_by_name_as_caught() -> None:
    item = kit.scenario("smoke-sql-direct")
    found = [{"rule": "persistence-sql-string-concat", "path": REPO, "line": 30, "cwe": []}]
    refused = {"refused": True, "output": "[deny: persistence-sql-string-concat CWE-89] ..."}
    graded = grading.grade(item, found, "unseen", refused)
    assert (graded["verdict"], graded["caught_at"]) == ("pass", "commit")
    unnamed = {"refused": True, "output": "some other hook failed"}
    assert grading.grade(item, found, "unseen", unnamed)["verdict"] == "fail"
    assert grading.grade(item, found, "unseen", None)["verdict"] == "fail"


def test_a_commit_gate_that_disagrees_with_the_engine_fails_the_scenario() -> None:
    item = kit.scenario("smoke-control-endpoint")
    graded = grading.grade(item, [], "silent", {"refused": True, "output": "blocked"})
    assert (graded["commit_agrees"], graded["verdict"]) == (False, "fail")
    assert "commit gate disagrees" in grading.cell({**graded, "gate_seen": "silent"})


@pytest.mark.skipif(shutil.which("chock") is None, reason="the repo route installs with chock")
def test_copilots_repo_route_catches_a_direct_construct_at_the_commit(tmp_path: Path, capsys) -> None:
    workspace = _workspace(tmp_path, route="repo", agent="copilot")
    kit.main(["start", "smoke-sql-direct", "--dir", str(workspace)])
    _add_query(workspace, BAD)
    kit.main(["record", "smoke-sql-direct", "--dir", str(workspace), "--gate", "unseen"])
    row = _row(workspace)
    assert (row["verdict"], row["caught_at"], row["commit_agrees"]) == ("pass", "commit", True)
    assert "the commit gate refused it by name" in capsys.readouterr().out

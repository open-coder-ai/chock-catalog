"""The gate prints a findings document; the engine, not the gate, judges what a change adds."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from agentic_code_security.conftest import GATE, commit
from agentic_gate import document
from agentic_gate.model import FileText, Finding
from policies import gatekit, scriptkit

NAME = "agentic-code-security"
HEAD_LINES = "import subprocess\nfrom langchain.tools import tool\n\n\n@tool\ndef run(cmd: str) -> str:\n"
TLS = "import requests\n\nrequests.get(u, verify=False)\n"
PATH = "agents/tool.py"
SHELL_KEY = "tools-shell-injection-via-tool-param|run|return subprocess.run(command, shell=True)"
DIFFED = "provenance-marker-removed"


def tool(*body: str) -> str:
    return HEAD_LINES + "".join(f"    {line}\n" for line in body)


OLD_FLOW = tool("command = cmd", "return subprocess.run(command, shell=True)")
FIXED_SQL = 'def f(cur, uid):\n    cur.execute(\n        "SELECT * FROM t WHERE id = %s",\n        f"{uid}",\n    )\n'
SWAPPED_SQL = FIXED_SQL.replace('        "SELECT * FROM t WHERE id = %s",\n', "")


def stdout_of(writes: dict[str, str], event: str = "commit", **extra: object) -> dict:
    payload = json.dumps({"event": event, "repo_root": ".", "writes": writes, **extra})
    proc = subprocess.run(
        [sys.executable, str(GATE)], input=payload, capture_output=True, text=True, check=False, timeout=60
    )
    return json.loads(proc.stdout)


def stop(repo: Path, writes: dict[str, str]) -> int:
    """The engine's verdict at the turn's end, with the writes on disk as the turn leaves them."""
    scriptkit.write(repo, writes)
    return gatekit.judge(NAME, repo, gatekit.STOP, writes)[0]


def test_the_document_keys_a_finding_by_rule_scope_and_line_without_a_line_number() -> None:
    (row,) = stdout_of({PATH: OLD_FLOW})["findings"]
    assert row["key"] == SHELL_KEY
    assert (row["path"], row["line"]) == (PATH, 8)
    assert row["message"].startswith("[deny: tools-shell-injection-via-tool-param")
    assert "new" not in row


def test_the_key_survives_a_line_shift() -> None:
    shifted = "# header\n# header\n" + OLD_FLOW
    assert stdout_of({PATH: shifted})["findings"][0]["key"] == SHELL_KEY


def test_a_class_and_a_function_are_both_in_the_scope() -> None:
    text = FileText("a.py", "class K:\n    @staticmethod\n    def f(u):\n        return 1\n\nx = 1\n")
    scope = document._scopes(text)
    assert [scope(n) for n in (1, 2, 3, 4, 6)] == ["K", "K.f", "K.f", "K.f", ""]


def test_other_files_have_no_scope() -> None:
    finding = Finding("r", "a.yaml", 1, "a:  1", "m")
    (row,) = document.document([finding], {"a.yaml": "a: 1\n"})["findings"]
    assert row["key"] == "r||a: 1"
    broken = Finding("r", "a.py", 1, "def (", "m")
    assert document.document([broken], {"a.py": "def ("})["findings"][0]["key"] == "r||def ("


def test_a_finding_that_compares_with_head_is_marked_new(tmp_path: Path) -> None:
    commit(tmp_path, {"a.py": "C2PA = 1\n"})
    payload = json.dumps({"event": "commit", "repo_root": str(tmp_path), "writes": {"a.py": "x = 1\n"}})
    proc = subprocess.run(
        [sys.executable, str(GATE)], input=payload, capture_output=True, text=True, check=False, timeout=60
    )
    (row,) = json.loads(proc.stdout)["findings"]
    assert (row["key"].split("|")[0], row["new"]) == (DIFFED, True)


def test_a_clean_write_prints_an_empty_document() -> None:
    assert stdout_of({"a.py": "x = 1\n"}) == {"findings": []}


def test_the_baseline_run_judges_as_the_change_run_does() -> None:
    assert stdout_of({PATH: OLD_FLOW}, baseline=True) == stdout_of({PATH: OLD_FLOW})


def test_the_finding_a_deleted_first_argument_uncovers_is_the_untouched_call() -> None:
    assert stdout_of({"db.py": FIXED_SQL}) == {"findings": []}
    (row,) = stdout_of({"db.py": SWAPPED_SQL})["findings"]
    assert (row["key"], row["line"]) == ("code-sql-string-built|f|cur.execute(", 2)


def test_deleting_the_line_that_kept_a_call_safe_is_refused(tmp_path: Path) -> None:
    commit(tmp_path, {"db.py": FIXED_SQL})
    assert stop(tmp_path, {"db.py": SWAPPED_SQL}) == 1


def test_an_old_violation_beside_an_unrelated_edit_passes(tmp_path: Path) -> None:
    commit(tmp_path, {"a.py": TLS, PATH: OLD_FLOW})
    assert stop(tmp_path, {"a.py": TLS + "x = 1\n", PATH: OLD_FLOW + "\n\ndef one() -> int:\n    return 1\n"}) == 0


def test_a_line_shift_of_an_old_violation_passes(tmp_path: Path) -> None:
    commit(tmp_path, {PATH: OLD_FLOW})
    assert stop(tmp_path, {PATH: "# header\n" + OLD_FLOW}) == 0


def test_a_second_copy_of_an_old_violation_is_refused(tmp_path: Path) -> None:
    commit(tmp_path, {"a.py": TLS})
    assert stop(tmp_path, {"a.py": TLS + "requests.get(u, verify=False)\n"}) == 1


def test_a_new_file_is_judged_whole(tmp_path: Path) -> None:
    commit(tmp_path, {"README.txt": "x\n"})
    assert stop(tmp_path, {"a.py": TLS}) == 1
    assert stop(tmp_path, {"b.py": "x = 1\n"}) == 0


def test_at_pre_tool_use_the_baseline_is_the_disk_not_head(tmp_path: Path) -> None:
    commit(tmp_path, {"a.py": "import requests\n"})
    scriptkit.write(tmp_path, {"a.py": TLS})
    assert gatekit.judge(NAME, tmp_path, gatekit.PRE_TOOL_USE, {"a.py": TLS + "x = 1\n"})[0] == 0
    assert stop(tmp_path, {"a.py": TLS + "x = 1\n"}) == 1


def test_a_staged_commit_is_judged_against_head(tmp_path: Path) -> None:
    commit(tmp_path, {"a.py": TLS})
    scriptkit.write(tmp_path, {"a.py": TLS + "x = 1\n"})
    scriptkit.git(tmp_path, "add", "-A")
    assert gatekit.judge(NAME, tmp_path, gatekit.COMMIT)[0] == 0
    scriptkit.write(tmp_path, {"a.py": TLS + TLS})
    scriptkit.git(tmp_path, "add", "-A")
    assert gatekit.judge(NAME, tmp_path, gatekit.COMMIT)[0] == 1


def test_a_removed_provenance_marker_is_new_whatever_the_baseline_holds(tmp_path: Path) -> None:
    commit(tmp_path, {"a.py": "C2PA = 1\n"})
    assert stop(tmp_path, {"a.py": "x = 1\n"}) == 1


def test_a_new_line_that_binds_the_memory_client_makes_old_calls_findings(tmp_path: Path) -> None:
    before = "from mem0 import Memory\n\nmemory = build()\nmemory.add('x')\n"
    commit(tmp_path, {"m.py": before})
    (tmp_path / ".chock").mkdir()
    selection = {"version": 1, "packs": {"prompt-memory": {"verdict": "deny"}}}
    (tmp_path / ".chock" / "agentic-security.json").write_text(json.dumps(selection), encoding="utf-8")
    assert stop(tmp_path, {"m.py": before.replace("build()", "Memory()")}) == 1


def test_a_missing_repository_has_no_committed_text(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("agentic_code_security_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.committed(tmp_path / "absent")("a.py") is None

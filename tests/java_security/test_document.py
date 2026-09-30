"""The gate prints a findings document; the engine, not the gate, judges what a change adds."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from chock_security import document
from chock_security.decision import FileText, Finding
from java_security.conftest import GATE
from policies import gatekit, scriptkit

POLICY = "java-security"
PATH_RULE = "java-path-traversal-request-data"
XSS_RULE = "java-xss-writer"


def java(*body: str, param: str = "@RequestParam String name") -> str:
    lines = "".join(f"    {line}\n" for line in body)
    return f"class C {{\n  void get({param}) {{\n{lines}  }}\n}}\n"


SANITIZED = java("String s = name;", "s = Encode.forHtml(s);", "resp.getWriter().println(s);")
UNSANITIZED = java("String s = name;", "resp.getWriter().println(s);")
GUARDED = java('String q = ALLOWED.contains(name) ? name : "x";', "new File(q);")
UNGUARDED = java("String q = name;", "new File(q);")
OLD = java("new File(name);")
OLD_HTML = '<p th:utext="${bio}"></p>\n'


def stdout_of(text: str, path: str = "C.java", **extra: object) -> dict:
    payload = json.dumps({"event": "commit", "repo_root": ".", "writes": {path: text}, **extra})
    proc = subprocess.run(  # noqa: S603 -- the shipped gate, run as a hook runner does
        [sys.executable, str(GATE)], input=payload, capture_output=True, text=True, check=False, timeout=60
    )
    return json.loads(proc.stdout)


def repo_at(tmp_path: Path, files: dict[str, str]) -> Path:
    return scriptkit.init_repo(tmp_path / "r", files)


def stop(repo: Path, writes: dict[str, str]) -> int:
    """The engine's verdict at the turn's end, with the writes on disk as the turn leaves them."""
    scriptkit.write(repo, writes)
    return gatekit.judge(POLICY, repo, gatekit.STOP, writes)[0]


def test_the_document_holds_a_key_per_finding_and_no_line_number() -> None:
    (row,) = stdout_of(UNSANITIZED)["findings"]
    assert row["key"] == f"{XSS_RULE}|get|resp.getWriter().println(s);"
    assert (row["path"], row["line"]) == ("C.java", 4)
    assert row["message"].startswith(f"[deny: {XSS_RULE} CWE-79]")


def test_the_key_survives_a_line_shift_and_a_reindent() -> None:
    shifted = UNSANITIZED.replace("class C {", "class C {\n  int one;\n").replace("    resp", "        resp")
    assert stdout_of(shifted)["findings"][0]["key"] == stdout_of(UNSANITIZED)["findings"][0]["key"]


def test_a_finding_outside_a_method_has_an_empty_scope() -> None:
    (row,) = stdout_of(OLD_HTML, "p.html")["findings"]
    assert row["key"].startswith("java-xss-unescaped-template||")


def test_a_clean_write_prints_an_empty_document() -> None:
    assert stdout_of(SANITIZED) == {"findings": []}


def test_the_baseline_run_judges_as_the_change_run_does() -> None:
    assert stdout_of(UNSANITIZED, baseline=True) == stdout_of(UNSANITIZED)


def test_a_waived_line_is_waived_in_both_runs() -> None:
    waived = OLD_HTML.rstrip() + " <!-- chock: allow java-xss-unescaped-template -->\n"
    assert stdout_of(waived) == stdout_of(waived, baseline=True) == {"findings": []}


def test_the_flagged_line_is_keyed_with_its_whitespace_collapsed() -> None:
    finding = Finding("r", "C.java", 4, "  x(   1 )", "m")
    (row,) = document.document([finding], [FileText("C.java", UNSANITIZED)])["findings"]
    assert row["key"] == "r|get|x( 1 )"


@pytest.mark.parametrize(("head", "written"), [(SANITIZED, UNSANITIZED), (GUARDED, UNGUARDED)])
def test_deleting_the_line_that_made_a_sink_safe_is_refused(tmp_path: Path, head: str, written: str) -> None:
    repo = repo_at(tmp_path, {"C.java": head})
    assert stop(repo, {"C.java": written}) == 1


def test_an_old_violation_beside_an_unrelated_edit_passes(tmp_path: Path) -> None:
    repo = repo_at(tmp_path, {"C.java": OLD, "p.html": OLD_HTML})
    edited = {"C.java": OLD.replace("class C {", "class C {\n  int one;"), "p.html": OLD_HTML + "<p>x</p>\n"}
    assert stop(repo, edited) == 0


def test_a_line_shift_of_an_old_violation_passes(tmp_path: Path) -> None:
    repo = repo_at(tmp_path, {"C.java": OLD})
    assert stop(repo, {"C.java": "// header\n// header\n" + OLD}) == 0


def test_a_second_copy_of_an_old_violation_is_refused(tmp_path: Path) -> None:
    repo = repo_at(tmp_path, {"p.html": OLD_HTML})
    assert stop(repo, {"p.html": OLD_HTML + OLD_HTML}) == 1


def test_an_old_violation_beside_a_new_one_names_only_the_new(tmp_path: Path) -> None:
    repo = repo_at(tmp_path, {"C.java": OLD})
    both = OLD.replace("new File(name);", "new File(name);\n    Runtime.getRuntime().exec(name);")
    scriptkit.write(repo, {"C.java": both})
    code, err = gatekit.judge(POLICY, repo, gatekit.STOP, {"C.java": both})
    assert code == 1
    assert "java-command-injection" in err
    assert PATH_RULE not in err


def test_at_pre_tool_use_the_baseline_is_the_disk_not_head(tmp_path: Path) -> None:
    repo = repo_at(tmp_path, {"p.html": "<p>x</p>\n"})
    scriptkit.write(repo, {"p.html": OLD_HTML})
    assert gatekit.judge(POLICY, repo, gatekit.PRE_TOOL_USE, {"p.html": OLD_HTML + "<p>y</p>\n"})[0] == 0
    assert stop(repo, {"p.html": OLD_HTML + "<p>y</p>\n"}) == 1


def test_a_staged_commit_is_judged_against_head(tmp_path: Path) -> None:
    repo = repo_at(tmp_path, {"p.html": OLD_HTML})
    scriptkit.write(repo, {"p.html": OLD_HTML + "<p>y</p>\n"})
    scriptkit.git(repo, "add", "-A")
    assert gatekit.judge(POLICY, repo, gatekit.COMMIT)[0] == 0
    scriptkit.write(repo, {"p.html": OLD_HTML + OLD_HTML})
    scriptkit.git(repo, "add", "-A")
    assert gatekit.judge(POLICY, repo, gatekit.COMMIT)[0] == 1


def test_a_new_file_is_judged_whole(tmp_path: Path) -> None:
    repo = repo_at(tmp_path, {"README.txt": "x\n"})
    assert stop(repo, {"p.html": OLD_HTML}) == 1
    assert stop(repo, {"q.html": "<p>x</p>\n"}) == 0

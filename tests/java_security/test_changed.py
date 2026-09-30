"""The gate judges what a change adds: an old violation in a touched file passes, a new one is refused."""

from __future__ import annotations

from pathlib import Path

import pytest
from chock_security import changed
from chock_security.decision import FileText, Finding
from chock_security.flow import methods, reaching
from java_security.conftest import run_gate
from policies import scriptkit

REFUSE, PASS = 1, 0
PATH_RULE = "java-path-traversal-request-data"
XSS_RULE = "java-xss-unescaped-template"


def java(*body: str, param: str = "@RequestParam String name") -> str:
    lines = "".join(f"    {line}\n" for line in body)
    return f"class C {{\n  void get({param}) {{\n{lines}  }}\n}}\n"


OLD_FLOW = java("String p = name;", "new File(p);")
CLEAN_FLOW = java('String p = "fixed";', "new File(p);")
OLD_HTML = '<p th:utext="${bio}"></p>\n'
CLEAN_HTML = '<p th:text="${name}"></p>\n'


def repo_with(tmp_path: Path, files: dict[str, str]) -> Path:
    return scriptkit.init_repo(tmp_path / "r", files)


def judge(repo: Path, writes: dict[str, str], event: str, land: bool = False) -> tuple[int, str]:
    """The gate's verdict; `land` puts the writes on disk first, as the turn's end finds them."""
    if land:
        scriptkit.write(repo, writes)
    return run_gate(repo, writes, event=event)


@pytest.mark.parametrize("event", ["commit", "tool_use"])
def test_an_old_violation_beside_an_unrelated_new_line_passes(tmp_path: Path, event: str) -> None:
    repo = repo_with(tmp_path, {"C.java": OLD_FLOW, "p.html": OLD_HTML})
    edited = {"C.java": OLD_FLOW.replace("class C {", "class C {\n  int one;"), "p.html": OLD_HTML + CLEAN_HTML}
    assert judge(repo, edited, event)[0] == PASS


def test_an_old_violation_passes_at_the_turns_end_when_disk_holds_the_write(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"p.html": OLD_HTML})
    assert judge(repo, {"p.html": OLD_HTML + CLEAN_HTML}, "tool_use", land=True)[0] == PASS


@pytest.mark.parametrize("event", ["commit", "tool_use"])
def test_a_new_violation_is_refused(tmp_path: Path, event: str) -> None:
    repo = repo_with(tmp_path, {"p.html": CLEAN_HTML})
    code, err = judge(repo, {"p.html": CLEAN_HTML + OLD_HTML}, event)
    assert code == REFUSE
    assert f"p.html:2: [deny: {XSS_RULE}" in err


def test_a_new_violation_is_refused_at_the_turns_end_against_head(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"p.html": OLD_HTML})
    two = OLD_HTML + OLD_HTML
    assert judge(repo, {"p.html": two}, "tool_use", land=True)[0] == REFUSE


@pytest.mark.parametrize("event", ["commit", "tool_use"])
def test_an_edit_to_a_clean_file_passes(tmp_path: Path, event: str) -> None:
    repo = repo_with(tmp_path, {"p.html": CLEAN_HTML, "C.java": CLEAN_FLOW})
    edited = {"p.html": CLEAN_HTML + CLEAN_HTML, "C.java": CLEAN_FLOW.replace("class C {", "class C {\n  int one;")}
    assert judge(repo, edited, event)[0] == PASS


@pytest.mark.parametrize("event", ["commit", "tool_use"])
def test_a_new_file_is_judged_whole(tmp_path: Path, event: str) -> None:
    repo = repo_with(tmp_path, {"README.txt": "x\n"})
    assert judge(repo, {"p.html": OLD_HTML + CLEAN_HTML}, event)[0] == REFUSE
    assert judge(repo, {"p.html": CLEAN_HTML}, event)[0] == PASS


def test_at_tool_use_the_baseline_is_the_disk_not_head(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"p.html": CLEAN_HTML})
    scriptkit.write(repo, {"p.html": CLEAN_HTML + OLD_HTML})
    assert judge(repo, {"p.html": CLEAN_HTML + OLD_HTML + CLEAN_HTML}, "tool_use")[0] == PASS
    assert judge(repo, {"p.html": CLEAN_HTML + OLD_HTML + CLEAN_HTML}, "commit")[0] == REFUSE


@pytest.mark.parametrize("event", ["commit", "tool_use"])
def test_a_source_line_that_completes_a_flow_into_an_old_sink_is_refused(tmp_path: Path, event: str) -> None:
    repo = repo_with(tmp_path, {"C.java": CLEAN_FLOW})
    code, err = judge(repo, {"C.java": OLD_FLOW}, event)
    assert code == REFUSE
    assert f"C.java:4: [deny: {PATH_RULE}" in err


@pytest.mark.parametrize("event", ["commit", "tool_use"])
def test_a_new_sink_fed_by_an_old_source_is_refused(tmp_path: Path, event: str) -> None:
    repo = repo_with(tmp_path, {"C.java": java("String p = name;", "log(p);")})
    assert judge(repo, {"C.java": java("String p = name;", "log(p);", "new File(p);")}, event)[0] == REFUSE


@pytest.mark.parametrize("event", ["commit", "tool_use"])
def test_a_hop_in_the_middle_of_a_flow_counts_as_part_of_it(tmp_path: Path, event: str) -> None:
    before = java("String p = name;", 'String q = "fixed";', "new File(q);")
    after = java("String p = name;", "String q = p;", "new File(q);")
    repo = repo_with(tmp_path, {"C.java": before})
    assert judge(repo, {"C.java": after}, event)[0] == REFUSE


@pytest.mark.parametrize("event", ["commit", "tool_use"])
def test_an_annotation_added_to_the_signature_makes_the_old_sink_new(tmp_path: Path, event: str) -> None:
    repo = repo_with(tmp_path, {"C.java": java("new File(name);", param="String name")})
    assert judge(repo, {"C.java": java("new File(name);")}, event)[0] == REFUSE


def test_an_unrelated_method_added_beside_an_old_flow_passes(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"C.java": OLD_FLOW})
    after = OLD_FLOW.rstrip().removesuffix("}") + "\n  int one() {\n    return 1;\n  }\n}\n"
    assert judge(repo, {"C.java": after}, "commit")[0] == PASS


def test_a_reindented_old_violation_is_still_old(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"p.html": OLD_HTML})
    assert judge(repo, {"p.html": "  " + OLD_HTML}, "commit")[0] == PASS


def test_the_flow_records_the_lines_it_came_through() -> None:
    (method,) = methods(FileText("C.java", java("String p = name;", "String q = p;", "new File(q);")))
    (flow,) = reaching(method, ["new File("])
    assert (method.header, flow.line_no, flow.related) == ((2,), 5, (2, 3, 4))


def test_a_flow_fed_by_a_source_call_has_no_lines_but_its_own() -> None:
    text = FileText("C.java", java('new File(request.getParameter("n"));', param="int n"))
    (method,) = methods(text)
    (flow,) = reaching(method, ["new File("])
    assert flow.related == ()


def test_a_reassignment_that_cleans_the_value_ends_the_trail() -> None:
    text = FileText("C.java", java("String p = name;", 'p = "x";', "new File(p);"))
    (method,) = methods(text)
    assert list(reaching(method, ["new File("])) == []


def test_new_lines_counts_copies_and_ignores_indentation() -> None:
    assert changed.new_lines(["a", "b"], None) == {1, 2}
    assert changed.new_lines(["a", "a", "b"], "a\nb\n") == {2}
    assert changed.new_lines(["  a", "b"], "a\n  b\n") == set()


def test_a_statement_spans_its_continuation_lines() -> None:
    text = FileText("C.java", "class C {\n  void f() {\n    call(a,\n         b,\n         c);\n    done();\n  }\n}\n")
    assert changed.statement(text, 4) == range(3, 6)
    assert changed.statement(text, 6) == range(6, 7)
    assert changed.statement(text, 99) == range(99, 100)


def test_a_statement_stops_at_a_blank_line_and_at_the_span_limit() -> None:
    text = FileText("C.java", "a(\n\nb(\n" + "".join(f"  x{i},\n" for i in range(50)) + ");\n")
    assert changed.statement(text, 1) == range(1, 2)
    assert changed.statement(text, 4) == range(4, 5)


def test_only_java_has_statements() -> None:
    assert changed.statement(FileText("a.properties", "k=v,\nw=z\n"), 1) == range(1, 2)


def test_a_change_inside_a_multi_line_statement_is_a_change_to_a_finding_on_its_first_line() -> None:
    text = FileText("C.java", "class C {\n  void f() {\n    call(a,\n         b);\n  }\n}\n")
    finding = Finding("r", "C.java", 3, "call(a,", "m")
    before = "class C {\n  void f() {\n    call(a,\n         old);\n  }\n}\n"
    assert changed.only_new([finding], [text], {"C.java": before}) == [finding]
    assert changed.only_new([finding], [text], {"C.java": text.text}) == []


def test_the_baseline_reads_disk_only_at_tool_use(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("disk", encoding="utf-8")
    head = {"a.txt": "head", "gone.txt": "head"}.get
    assert changed.baseline(tmp_path, "a.txt", "new", "tool_use", head) == "disk"
    assert changed.baseline(tmp_path, "a.txt", "disk", "tool_use", head) == "head"
    assert changed.baseline(tmp_path, "a.txt", "new", "commit", head) == "head"
    assert changed.baseline(tmp_path, "gone.txt", "new", "tool_use", head) == "head"
    assert changed.baseline(tmp_path, "none.txt", "new", "tool_use", head) is None
    assert changed.on_disk(tmp_path, "none.txt") is None

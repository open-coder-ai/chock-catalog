"""The flow model the request-data rules share: what it reads as a method, and what it taints."""

from __future__ import annotations

from chock_security.decision import FileText
from chock_security.engine import evaluate
from chock_security.flow import flows, methods
from java_security.conftest import ALL_DENY

SINKS = ["Paths.get("]


def _controller(param: str, body: str) -> str:
    return f'public class C {{\n  @GetMapping("/x")\n  public Object x({param}) throws Exception {{\n    {body}\n  }}\n}}\n'


def test_a_one_line_method_has_a_body() -> None:
    text = FileText(
        "C.java", 'class C {\n  int a(@RequestParam String f) { return open(Paths.get("/srv/" + f)); }\n}\n'
    )
    assert [m.name for m in methods(text)] == ["a"]
    assert [f.line_no for f in flows(text, SINKS)] == [2]


def test_back_to_back_one_line_methods_are_each_read() -> None:
    line = '  byte[] {n}(@RequestParam String f) {{ return read(Paths.get("/srv/" + f)); }}\n'
    text = FileText("C.java", "class C {\n" + line.format(n="a") + line.format(n="b") + "}\n")
    assert [m.name for m in methods(text)] == ["a", "b"]


def test_a_parameter_typed_as_a_number_or_uuid_taints_nothing() -> None:
    for declared in ("@PathVariable Long id", "@PathVariable int id", '@PathVariable("id") UUID id'):
        body = _controller(declared, 'return Files.readAllBytes(Paths.get("/srv/" + id + ".png"));')
        assert not list(flows(FileText("C.java", body), SINKS)), declared


def test_a_string_parameter_still_taints() -> None:
    body = _controller("@PathVariable String id", 'return Files.readAllBytes(Paths.get("/srv/" + id));')
    assert len(list(flows(FileText("C.java", body), SINKS))) == 1


def test_a_pack_sanitizer_holds_through_an_assignment() -> None:
    body = _controller(
        "@RequestParam String q", "String safe = LdapEncoder.filterEncode(q);\n    ctx.search(base, safe, controls);"
    )
    text = FileText("C.java", body)
    assert list(flows(text, [".search("]))
    assert not list(flows(text, [".search("], sanitizers=("LdapEncoder.",)))


def test_a_declaration_without_a_body_is_not_a_method() -> None:
    assert methods(FileText("I.java", "interface I {\n  String find(String q);\n}\n")) == []


def test_nothing_fires_on_an_empty_write() -> None:
    assert evaluate([FileText("Empty.java", "")], ALL_DENY) == []


def test_a_parameter_list_over_several_lines_is_read_whole() -> None:
    text = FileText(
        "C.java",
        "class C {\n  Object x(\n      @RequestParam String f,\n      int n) {\n"
        '    return read(Paths.get("/srv/" + f));\n  }\n}\n',
    )
    assert [m.name for m in methods(text)] == ["x"]
    assert [f.line_no for f in flows(text, SINKS)] == [5]


def test_a_brace_on_its_own_line_opens_the_body() -> None:
    text = FileText(
        "C.java",
        'class C {\n  Object x(@RequestParam String f)\n  {\n    return read(Paths.get("/srv/" + f));\n  }\n}\n',
    )
    assert [f.line_no for f in flows(text, SINKS)] == [4]


def test_a_signature_still_being_typed_is_no_method() -> None:
    text = FileText("C.java", "class C {\n  Object x(@RequestParam String f,\n")
    assert methods(text) == []


def test_a_body_still_being_typed_is_no_method() -> None:
    text = FileText("C.java", 'class C {\n  Object x(@RequestParam String f) {\n    read(Paths.get("/srv/" + f));\n')
    assert methods(text) == []


def test_an_annotation_with_no_parameter_behind_it_taints_nothing() -> None:
    text = FileText(
        "C.java", 'class C {\n  Object x(@RequestParam) {\n    return read(Paths.get("/srv/" + f));\n  }\n}\n'
    )
    assert [m.name for m in methods(text)] == ["x"]
    assert list(flows(text, SINKS)) == []

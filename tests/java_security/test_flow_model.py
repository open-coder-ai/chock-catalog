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


def test_a_membership_check_guards_the_value_whatever_the_collection_is_called() -> None:
    body = 'String target = ALLOWED.contains(next) ? next : "/orders";\n    return read(Paths.get(target));'
    assert list(flows(FileText("C.java", _controller("@RequestParam String next", body)), SINKS)) == []
    unguarded = 'String target = ALLOWED.contains(other) ? next : "/orders";\n    return read(Paths.get(target));'
    assert [
        f.line_no for f in flows(FileText("C.java", _controller("@RequestParam String next", unguarded)), SINKS)
    ] == [5]


def test_a_name_inside_a_string_literal_is_not_a_use_of_the_parameter() -> None:
    body = 'return read(Paths.get("/srv/f.txt"), "name=$f");'
    assert list(flows(FileText("C.java", _controller("@RequestParam String f", body)), SINKS)) == []


def test_matches_with_no_pattern_is_the_match_not_a_validation() -> None:
    compiled = FileText(
        "C.java", _controller("@RequestParam String p", "return Pattern.compile(p).matcher(s).matches();")
    )
    assert [f.line_no for f in flows(compiled, ["Pattern.compile("])] == [4]
    checked = FileText(
        "C.java",
        _controller(
            "@RequestParam String f",
            "String safe = f.matches(SAFE_NAME) ? f : null;\n    return read(Paths.get(safe));",
        ),
    )
    assert list(flows(checked, SINKS)) == []


def _flow_lines(param: str, body: str, sinks: list[str] = SINKS, **kwargs: tuple[str, ...]) -> list[int]:
    return [f.line_no for f in flows(FileText("C.java", _controller(param, body)), sinks, **kwargs)]


def test_a_sanitizer_named_in_a_comment_or_literal_is_not_a_sanitizer() -> None:
    for line in (
        'return read(Paths.get("/srv/" + f)); // TODO sanitize later',
        'return read(Paths.get("/srv/" + f)); /* f.normalize() */',
        'return read(Paths.get("/srv/sanitize(f)/" + f));',
        "return read(Paths.get(\"/srv/\" + f)); char c = 'x'; // isValid(f)",
        'return read(Paths.get("/srv/" + f)); String t = """\n    sanitize(f)\n    """;',
    ):
        assert _flow_lines("@RequestParam String f", line) == [4], line


def test_a_block_comment_that_opens_on_an_earlier_line_hides_its_text() -> None:
    body = '/*\n    sanitize(f)\n    */ return read(Paths.get("/srv/" + f));'
    assert _flow_lines("@RequestParam String f", body) == [6]


def test_a_sanitizer_must_be_applied_to_the_value_the_line_carries() -> None:
    assert _flow_lines("@RequestParam String f", 'sanitize(g); return read(Paths.get("/srv/" + f));') == [4]
    assert _flow_lines("@RequestParam String f", 'return read(Paths.get(sanitize(g) + "/" + f));') == [4]
    assert _flow_lines("@RequestParam String f", 'return read(Paths.get("/srv/" + sanitize(f)));') == []
    assert _flow_lines("@RequestParam String f", 'if (valid.isValid(f)) return read(Paths.get("/srv/" + f));') == []
    assert _flow_lines("@RequestParam String f", 'return read(Paths.get(f.normalize() + "/srv"));') == []


def test_a_name_that_only_contains_a_sanitizer_word_is_not_a_call_to_it() -> None:
    body = 'String unsanitized = f;\n    return read(Paths.get("/srv/" + unsanitized));'
    assert _flow_lines("@RequestParam String f", body) == [5]


def test_a_check_on_a_request_read_counts_and_a_comment_beside_it_does_not() -> None:
    clean = 'return read(Paths.get("/srv", FilenameUtils.getName(request.getParameter("f"))));'
    assert _flow_lines("HttpServletRequest request", clean) == []
    commented = 'return read(Paths.get("/srv", request.getParameter("f"))); // sanitize'
    assert _flow_lines("HttpServletRequest request", commented) == [4]


def test_a_method_on_an_indexed_receiver_is_read() -> None:
    assert _flow_lines("@RequestParam String[] f", 'return read(Paths.get(f[0].normalize() + "/x"));') == []
    assert _flow_lines("@RequestParam String[] f", "return read(Paths.get(g[0].normalize() + f[0]));") == [4]


def test_a_call_continued_from_an_earlier_line_is_not_credited_with_the_value() -> None:
    body = 'a).normalize(); return read(Paths.get("/srv/" + f));'
    assert _flow_lines("@RequestParam String f", body) == [4]


def test_a_call_whose_arguments_are_still_open_is_read_to_the_line_end() -> None:
    assert _flow_lines("@RequestParam String f", 'return read(Paths.get(sanitize(f + "/x"') == []
    assert _flow_lines("@RequestParam String f", 'return read(Paths.get("/srv/" + f, sanitize(') == [4]


def test_a_pack_sanitizer_must_be_applied_to_the_value() -> None:
    param = "@RequestParam String q"
    sinks = [".search("]
    applied = "String safe = LdapEncoder.filterEncode(q);\n    ctx.search(base, safe, controls);"
    assert _flow_lines(param, applied, sinks, sanitizers=("LdapEncoder",)) == []
    for body in (
        "String safe = LdapEncoder.filterEncode(other);\n    ctx.search(base, q, controls);",
        "// LdapEncoder.filterEncode(q)\n    ctx.search(base, q, controls);",
        'ctx.search(base, q, controls); String n = "LdapEncoder";',
    ):
        assert _flow_lines(param, body, sinks, sanitizers=("LdapEncoder",)), body
    builder = 'ctx.search(base, query().where("uid").is(q), controls);'
    assert _flow_lines(param, builder, sinks, sanitizers=(".is(",)) == []
    assert _flow_lines(param, builder, sinks)


def test_lines_the_lexer_merges_are_never_credited_with_a_sanitizer() -> None:
    body = 'String a = "x"; // note\x0c\n    return read(Paths.get("/srv/" + sanitize(f)));'
    assert _flow_lines("@RequestParam String f", body) == [6]
    assert _flow_lines("@RequestParam String f", 'return read(Paths.get("/srv/" + sanitize(f)));') == []

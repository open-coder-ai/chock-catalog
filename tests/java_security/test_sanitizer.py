"""What the flow model credits as a check: one the sink takes the request value through, read as javac reads it."""

from __future__ import annotations

from chock_security.decision import FileText
from chock_security.flow import flows

SINKS = ["Paths.get("]


def _flow_lines(param: str, body: str, sinks: list[str] = SINKS, **kwargs: tuple[str, ...]) -> list[int]:
    text = f'public class C {{\n  @GetMapping("/x")\n  public Object x({param}) throws Exception {{\n    {body}\n  }}\n}}\n'
    return [f.line_no for f in flows(FileText("C.java", text), sinks, **kwargs)]


F = "@RequestParam String f"


def test_a_sanitizer_whose_result_is_thrown_away_is_not_a_sanitizer() -> None:
    for body in (
        'sanitize(f); return read(Paths.get("/srv/" + f));',
        'log.info(sanitize(f)); return read(Paths.get("/srv/" + f));',
        'return read(Paths.get("/srv/" + f, sanitize(f)));',
        'return read(Paths.get("/srv/" + f + FilenameUtils.getName(f).substring(0, 0)));',
        "return read(Paths.get(sanitize(f)).resolve(f));",
        'String s = sanitize(f), t = f; return read(Paths.get("/srv/" + t));',
    ):
        assert _flow_lines(F, body), body
    for body in (
        'return read(Paths.get("/srv/", sanitize(f)));',
        'String s = sanitize(f); return read(Paths.get("/srv/", s));',
        'return read(Paths.get("/srv/", sanitize(f)).resolve("index.html"));',
    ):
        assert _flow_lines(F, body) == [], body


def test_starts_with_counts_only_as_a_guard_on_the_value_itself() -> None:
    for body in (
        'f.startsWith("x"); return read(Paths.get("/srv/" + f));',
        'return read(Paths.get("/srv/" + f + ("".startsWith(f) ? "" : "")));',
        'return read(Paths.get("/srv/" + f + (isValid(f == null) ? "" : "")));',
        'if (f.isEmpty()) log(); return read(Paths.get("/srv/" + f));',
        'if (ok(sanitize(f))) return read(Paths.get("/srv/" + f));',
    ):
        assert _flow_lines(F, body), body
    for body in (
        'if (f.startsWith("docs")) return read(Paths.get("/srv/" + f));',
        'return read(Paths.get(f.startsWith("docs") ? f : "index"));',
        'String p = f.startsWith("docs") ? f : "index"; return read(Paths.get(p));',
        'return f.startsWith("docs") ? read(Paths.get(f)) : null;',
    ):
        assert _flow_lines(F, body) == [], body


def test_a_normalized_path_checked_with_starts_with_on_later_lines_still_passes() -> None:
    body = (
        "Path p = base.resolve(f).normalize();\n"
        '    if (!p.startsWith(base)) throw new IllegalArgumentException("outside");\n'
        "    return Files.readAllBytes(p);"
    )
    assert _flow_lines(F, body, ["base.resolve(", "Files.readAllBytes("]) == []


def test_a_ternary_is_found_among_generics_and_kotlin_null_operators() -> None:
    assert _flow_lines(F, 'return read(Paths.get(f.startsWith("a") ? f : "b"));') == []
    assert _flow_lines(F, "return read(Paths.get(m?.name + f));") == [4]
    assert _flow_lines(F, "Map<String, ?> m = null; return read(Paths.get(m + f));") == [4]
    assert _flow_lines(F, 'x = 1; y = f.startsWith("a") ? f : "b"; return read(Paths.get(y));') == []
    assert _flow_lines(F, 'return read(Paths.get(\n        f.startsWith("a") ? f : "b"));') == []


def test_a_sanitizer_is_a_whole_name_never_the_tail_of_one() -> None:
    for body in (
        'return read(Paths.get("/srv/", desanitize(f)));',
        'return read(Paths.get("/srv/", notisValid(f) ? f : "x"));',
    ):
        assert _flow_lines(F, body) == [4], body
    for body in (
        'return read(Paths.get("/srv/", this.sanitize(f)));',
        'return read(Paths.get("/srv/", Util.<String>sanitize(f)));',
        'return read(Paths.get("/srv/", validator.isValid(f) ? f : "x"));',
    ):
        assert _flow_lines(F, body) == [], body


def test_space_before_a_chained_sanitizer_is_skipped() -> None:
    assert _flow_lines(F, "return read(Paths.get(base, f) .getFileName());") == []
    assert _flow_lines(F, "return read(Paths.get(base, f) .toString());") == [4]


def test_a_sanitizer_reached_through_a_chain_of_calls_taking_nothing() -> None:
    sinks, esapi = ["resp.getWriter().println("], ("ESAPI.encoder(",)
    body = "resp.getWriter().println(ESAPI.encoder().encodeForHTML(f));"
    assert _flow_lines(F, body, sinks, sanitizers=esapi) == []
    assert _flow_lines(F, body, sinks) == [4]
    for raw in (
        "resp.getWriter().println(ESAPI.encoder().encodeForHTML(g) + f);",
        "resp.getWriter().println(ESAPI.encoder() + f);",
    ):
        assert _flow_lines(F, raw, sinks, sanitizers=esapi) == [4], raw
    chained = 'return read(Paths.get("/srv/", sanitizer().clean(f)));'
    assert _flow_lines(F, chained) == []


def test_a_sink_without_a_parenthesis_takes_the_rest_of_its_expression() -> None:
    sinks = ['"redirect:" +']
    assert _flow_lines(F, 'return "redirect:" + f;', sinks) == [4]
    assert _flow_lines(F, 'return "redirect:" + sanitize(f);', sinks) == []
    assert _flow_lines(F, 'return new View("redirect:" + sanitize(f), f.length());', sinks) == []


def test_a_value_assigned_earlier_on_the_line_reaches_the_sink_through_its_name() -> None:
    assert _flow_lines(F, 'String g = f; return read(Paths.get("/srv/", g));') == [4]
    assert _flow_lines(F, 'String g = sanitize(f); return read(Paths.get("/srv/", g));') == []
    assert _flow_lines(F, 'String g = f; return read(Paths.get("/srv/", "x"));') == []


def test_every_sink_on_the_line_must_take_the_value_through_a_check() -> None:
    assert _flow_lines(F, 'return read(Paths.get("/srv/", sanitize(f)), Paths.get(f));') == [4]
    assert _flow_lines(F, 'return read(Paths.get("/srv/", sanitize(f)), Paths.get("x"));') == []


def test_a_sink_called_on_request_data_takes_it() -> None:
    sinks = [".render("]
    assert _flow_lines(F, "return compile(f).render(model);", sinks) == [4]
    assert _flow_lines(F, "return compile(sanitize(f)).render(model);", sinks) == []


def test_a_variable_named_like_a_sanitizer_or_a_check_on_another_value_is_not_one() -> None:
    assert _flow_lines(F, 'String sanitized = f; return read(Paths.get("/srv/" + sanitized));') == [4]
    assert _flow_lines(F, 'return read(Paths.get(g.matches(SAFE_NAME) ? f : "x"));') == [4]
    assert _flow_lines(F, 'return read(Paths.get(f.matches(SAFE_NAME) ? f : "x"));') == []


def test_a_unicode_escape_is_read_the_way_javac_reads_it() -> None:
    hidden = '// ok \\u000a return read(Paths.get("/srv/" + f));'
    assert _flow_lines(F, hidden) == [4]
    commented = 'return read(Paths.get("/srv/" + f)); \\u002f\\u002f sanitize(f)'
    assert _flow_lines(F, commented) == [4]
    closed = 'return read(Paths.get("/srv/", sanitize(f\\u0029 + f));'
    assert _flow_lines(F, closed) == [4]
    for clean in (
        '// ok \\u000a return read(Paths.get("/srv/", sanitize(f)));',
        'String s = "\\u00e9"; return read(Paths.get("/srv/", sanitize(f)));',
        'String s = "\\\\u0022"; return read(Paths.get("/srv/", sanitize(f)));',
        'return read(Paths.get("/srv/", sanitize\\u0028f)));',
    ):
        assert _flow_lines(F, clean) == [], clean

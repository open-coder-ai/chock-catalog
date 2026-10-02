"""chock_scan.jsonc: comments, trailing commas, duplicates and every refusal, case by case."""

from __future__ import annotations

import ast
import copy
import pickle
import sys
from types import ModuleType

import pytest
from trees import ROOT

BOM = "\ufeff"


def test_comments_are_blanked_and_line_breaks_kept(jsonc: ModuleType) -> None:
    text = '{ // one\r\n  "a": /* two\n three */ 1 }'
    clean = jsonc.strip(text)
    assert clean == "{" + " " * 7 + '\r\n  "a": ' + " " * 6 + "\n" + " " * 9 + " 1 }"
    assert jsonc.loads(text) == ({"a": 1}, ())


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ('{"u": "http://x/*y*/"}', {"u": "http://x/*y*/"}),
        ('{"u": "a // b"}', {"u": "a // b"}),
        ('{"u": "\\"// still a string"}', {"u": '"// still a string'}),
        ('{"u": "ends in a backslash \\\\"} // comment', {"u": "ends in a backslash \\"}),
        ('{"u": "/* not */ a comment, ] }"}', {"u": "/* not */ a comment, ] }"}),
    ],
)
def test_comment_markers_inside_strings_are_kept(jsonc: ModuleType, text: str, value: object) -> None:
    assert jsonc.loads(text).value == value
    assert jsonc.strip(text).rstrip() == text.removesuffix(" // comment")


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("[1,]", [1]),
        ('{"a": 1,}', {"a": 1}),
        ("[1 , // c\n ]", [1]),
        ('{"a": [{},], /* c */ }', {"a": [{}]}),
        ('["s",]', ["s"]),
        ("[[1],]", [[1]]),
    ],
)
def test_a_trailing_comma_after_a_value_is_dropped(jsonc: ModuleType, text: str, value: object) -> None:
    assert jsonc.loads(text).value == value
    assert len(jsonc.strip(text)) == len(text)


@pytest.mark.parametrize("text", ["[,]", "{,}", "[1,,]", "[ , 1]", '{"a":,}', "[1,,2]"])
def test_a_comma_after_no_value_is_left_for_json_to_refuse(jsonc: ModuleType, text: str) -> None:
    with pytest.raises(jsonc.JsoncError):
        jsonc.loads(text)


def test_one_leading_bom_is_blanked_and_any_other_bom_refused(jsonc: ModuleType) -> None:
    assert jsonc.strip(BOM + "[1]") == " [1]"
    assert jsonc.loads(BOM + "[1]").value == [1]
    for text in (BOM + BOM + "[1]", "[1]" + BOM, "[" + BOM + "1]"):
        with pytest.raises(jsonc.JsoncError):
            jsonc.loads(text)


def test_the_last_duplicate_wins_and_every_duplicate_is_listed(jsonc: ModuleType) -> None:
    doc = jsonc.loads('{"hooks": {"cmd": "evil"}, "x": 1, "hooks": {}, "hooks": {"cmd": "ok"}}')
    assert doc.value == {"hooks": {"cmd": "ok"}, "x": 1}
    assert doc.duplicates == (jsonc.Duplicate(("hooks",), ({"cmd": "evil"}, {}, {"cmd": "ok"})),)


def test_duplicates_are_found_at_every_depth_and_inside_hidden_values(jsonc: ModuleType) -> None:
    text = '{"a": [0, {"k": 1, "k": 2}], "b": {"c": {"d": 1, "d": 2}}, "b": {"e": [{"f": 1, "f": 3}]}}'
    doc = jsonc.loads(text)
    assert doc.value == {"a": [0, {"k": 2}], "b": {"e": [{"f": 3}]}}
    assert [d.path for d in doc.duplicates] == [("a", 1, "k"), ("b",), ("b", "c", "d"), ("b", "e", 0, "f")]
    assert doc.duplicates[2].values == (1, 2)


def test_escaped_spellings_of_one_key_are_duplicates(jsonc: ModuleType) -> None:
    doc = jsonc.loads('{"env": 1, "\\u0065nv": 2, "e\\u006ev": 3}')
    assert doc.value == {"env": 3}
    assert doc.duplicates == (jsonc.Duplicate(("env",), (1, 2, 3)),)


def test_keys_differing_in_case_or_normalisation_are_not_duplicates(jsonc: ModuleType) -> None:
    assert jsonc.loads('{"Env": 1, "env": 2, "\\u00e9": 3, "e\\u0301": 4}').duplicates == ()


def test_an_identical_duplicate_is_still_reported(jsonc: ModuleType) -> None:
    assert jsonc.loads('{"a": 1, "a": 1}').duplicates == (jsonc.Duplicate(("a",), (1, 1)),)


@pytest.mark.parametrize(
    ("text", "msg", "line", "col"),
    [
        ('{"a": 1 /* open', "unterminated block comment", 1, 9),
        ("[1,\n /* x */ /*", "unterminated block comment", 2, 10),
        ('{"a": "b', "unterminated string", 1, 7),
        ('{"a": "b\n"}', "unterminated string", 1, 7),
        ('{"a": "b\r"}', "unterminated string", 1, 7),
        ('["\\', "unterminated string", 1, 2),
        ('["\\"]', "unterminated string", 1, 2),
        ("[1] // a\u2028b", "U+2028 in a // comment ends it for some loaders only", 1, 9),
        ("[1] // a\u2029b", "U+2029 in a // comment ends it for some loaders only", 1, 9),
        ('{} // c\r"x": 1', "a // comment ended by a lone CR ends there for some loaders only", 1, 8),
        ("[1]\r\n\r\n/*", "unterminated block comment", 3, 1),
        ("[1]\r\r/*", "unterminated block comment", 3, 1),
    ],
)
def test_unterminated_or_ambiguous_text_raises_with_its_position(
    jsonc: ModuleType, text: str, msg: str, line: int, col: int
) -> None:
    for call in (jsonc.strip, jsonc.loads):
        with pytest.raises(jsonc.JsoncError) as info:
            call(text)
        assert (info.value.msg, info.value.line, info.value.col) == (msg, line, col)
        assert str(info.value) == f"{msg} at line {line} column {col}"
        assert isinstance(info.value, ValueError)


def test_a_line_comment_may_end_with_crlf_or_at_the_end_of_the_text(jsonc: ModuleType) -> None:
    assert jsonc.loads("// c\r\n[1] // d").value == [1]
    assert jsonc.loads("[1] // d\r").value == [1]
    assert jsonc.loads('["\u2028 in a string is JSON"]').value == ["\u2028 in a string is JSON"]
    assert jsonc.loads("/* \u2028 */ [1]").value == [1]


@pytest.mark.parametrize(
    ("text", "line", "col"),
    [("", 1, 1), ("// only a comment", 1, 18), ('{\n  "a": 1\n  "b": 2}', 3, 3), ("[1] [2]", 1, 5)],
)
def test_invalid_json_raises_with_the_input_position(jsonc: ModuleType, text: str, line: int, col: int) -> None:
    with pytest.raises(jsonc.JsoncError) as info:
        jsonc.loads(text)
    assert (info.value.line, info.value.col) == (line, col)


@pytest.mark.parametrize("text", ["[NaN]", "[Infinity]", '{"a": -Infinity}'])
def test_python_only_constants_are_refused(jsonc: ModuleType, text: str) -> None:
    with pytest.raises(jsonc.JsoncError, match=r"is not JSON$") as info:
        jsonc.loads(text)
    assert (info.value.pos, info.value.line, info.value.col) == (None, None, None)


@pytest.mark.parametrize(
    "text", ["[1]\v", "[\f1]", "[\u00a01]", "{'a': 1}", "[01]", "[.5]", "[1] /", '["\t"]', '["\\x41"]', "[true1]"]
)
def test_what_json_refuses_is_refused_even_where_a_tolerant_loader_reads_on(jsonc: ModuleType, text: str) -> None:
    with pytest.raises(jsonc.JsoncError):
        jsonc.loads(text)


def test_the_size_limit_is_inclusive_and_counts_characters(jsonc: ModuleType) -> None:
    assert jsonc.loads("[1]", limit=3).value == [1]
    with pytest.raises(jsonc.JsoncError, match=r"^larger than 2 characters$") as info:
        jsonc.loads("[1]", limit=2)
    assert info.value.pos is None
    assert jsonc.LIMIT == 1 << 20
    assert jsonc.loads("[" + " " * (jsonc.LIMIT - 2) + "]").value == []
    with pytest.raises(jsonc.JsoncError, match="larger than 1048576 characters"):
        jsonc.strip(" " * (jsonc.LIMIT + 1))


def test_nesting_up_to_the_depth_cap_parses_and_one_more_is_refused(jsonc: ModuleType) -> None:
    deep = jsonc.MAX_DEPTH
    value: object = 1
    for _ in range(deep):
        value = {"a": value}
    assert jsonc.loads('{"a":' * deep + "1" + "}" * deep).value == value
    flat = jsonc.loads("[" * deep + "]" * deep).value
    for _ in range(deep - 1):
        assert isinstance(flat, list)
        (flat,) = flat
    assert flat == []
    with pytest.raises(jsonc.JsoncError, match=f"^nested deeper than {deep} at line 1 column {deep + 1}$"):
        jsonc.loads("[" * (deep + 1) + "]" * (deep + 1))
    assert jsonc.loads("[" + "[]," * 1000 + "[]]").value == [[]] * 1001


def test_a_number_or_literal_over_the_value_cap_is_refused(jsonc: ModuleType) -> None:
    cap = jsonc.MAX_VALUE
    assert jsonc.loads("[" + "9" * cap + "]").value == [int("9" * cap)]
    with pytest.raises(jsonc.JsoncError, match=f"longer than {cap} characters at line 1 column 2$"):
        jsonc.loads("[" + "9" * (cap + 1) + "]")
    assert len(jsonc.loads('["' + "x" * (cap * 10) + '"]').value[0]) == cap * 10


def test_unbalanced_closers_do_not_lower_the_depth_cap(jsonc: ModuleType) -> None:
    deep = jsonc.MAX_DEPTH
    with pytest.raises(jsonc.JsoncError, match=f"^nested deeper than {deep} at line 1 column {deep + 11}$"):
        jsonc.strip("]" * 10 + "[" * (deep + 1))
    with pytest.raises(jsonc.JsoncError):
        jsonc.loads("]]][[[")


def test_the_module_is_stdlib_only() -> None:
    tree = ast.parse((ROOT / "lib" / "chock_scan" / "jsonc.py").read_text(encoding="utf-8"))
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names == {"__future__", "json", "re", "typing"}
    assert {n.split(".")[0] for n in names} <= set(sys.stdlib_module_names)


@pytest.mark.parametrize(
    "text",
    [
        '{"__proto__": {"hooks": "evil"}}',
        '{"compilerOptions": {"\\u005f_proto__": {"plugins": [{"name": "x"}]}}}',
        '[{"__proto__": 1, "x": 2}]',
        '{"__proto__": {}, "__proto__": {}}',
    ],
)
def test_a_proto_key_is_refused_however_it_is_spelled(jsonc: ModuleType, text: str) -> None:
    with pytest.raises(jsonc.JsoncError, match=r"^a __proto__ key sets the prototype"):
        jsonc.loads(text)
    assert jsonc.loads('{"__proto": 1, "proto__": 2, "x": "__proto__"}').duplicates == ()


def test_duplicates_past_the_cap_are_refused_not_amplified(jsonc: ModuleType) -> None:
    cap = jsonc.MAX_DUPLICATES
    assert len(jsonc.loads("[" + ",".join(['{"a":1,"a":2}'] * cap) + "]").duplicates) == cap
    with pytest.raises(jsonc.JsoncError, match=f"^more than {cap} duplicate keys$"):
        jsonc.loads("[" + ",".join(['{"a":1,"a":2}'] * (cap + 1)) + "]")
    deep = "[" * 255 + ",".join(['{"a":1,"a":1}'] * 70000) + "]" * 255
    with pytest.raises(jsonc.JsoncError, match="duplicate keys"):
        jsonc.loads(deep)


def test_an_error_survives_pickle_and_copy(jsonc: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, jsonc.__name__, jsonc)  # the fixture loads by path; pickle imports by name
    for text in ("[1", "[NaN]"):
        with pytest.raises(jsonc.JsoncError) as info:
            jsonc.loads(text)
        for clone in (pickle.loads(pickle.dumps(info.value)), copy.copy(info.value)):  # noqa: S301 -- our own object
            assert (str(clone), clone.msg, clone.pos, clone.line, clone.col) == (
                str(info.value),
                info.value.msg,
                info.value.pos,
                info.value.line,
                info.value.col,
            )

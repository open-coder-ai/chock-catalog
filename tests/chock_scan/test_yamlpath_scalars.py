"""chock_scan.yamlpath scalars: block scalars, quoting, escapes and folding give the value a loader gives."""

from __future__ import annotations

from types import ModuleType

import pytest
from chock_scan.yamlkit import value_at


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("a: |\n  one\n   two\n\n  three\n", "one\n two\n\nthree\n"),
        ("a: |-\n  one\n\n", "one"),
        ("a: |+\n  one\n\n\nb: 1", "one\n\n\n"),
        ("a: |\n  one\n\n\n", "one\n"),
        ("a: |\n  one", "one"),
        ("a: |+\n  one", "one"),
        ("a: |+\n\n\nb: 1", "\n\n"),
        ("a: |\n\nb: 1", ""),
        ("a: |2\n    indented\n  base\n", "  indented\nbase\n"),
        ("a: |1-\n  x\n", " x"),
        ("a: |-1\n  x\n", " x"),
        ("- |\n  in a sequence\n- next", "in a sequence\n"),
        ("a: >\n  one\n  two\n\n  three\n    more\n  back\n", "one two\nthree\n  more\nback\n"),
        ("a: >-\n\n  lead\n  x\n", "\nlead x"),
        ("a: >\n  x\n\n\n    deep\n", "x\n\n\n  deep\n"),
        ("a: |\n  x\n   \n  y\n", "x\n \ny\n"),
        ("a: |\n  run: \t\n  # kept\n", "run: \t\n# kept\n"),
        ("a: |\n  \n  x\n", "\nx\n"),
        ("a:\n  |\n    own line\n", "own line\n"),
    ],
)
def test_block_scalars_follow_their_indicators(yp: ModuleType, text: str, value: str) -> None:
    path = (0,) if text.startswith("-") else ("a",)
    assert value_at(yp, text, path) == value


def test_a_block_scalar_ends_at_the_first_shallower_line(yp: ModuleType) -> None:
    found = yp.scan("a:\n  b: |\n    x\n  c: y\nd: >\n  z\n")
    assert [(n.path, n.value) for n in found if n.kind != "map"] == [
        (("a", "b"), "x\n"),
        (("a", "c"), "y"),
        (("d",), "z\n"),
    ]


def test_a_document_level_block_scalar(yp: ModuleType) -> None:
    assert [(n.value, n.kind) for n in yp.scan("--- >\n  folded\n  text\n")] == [("folded text\n", "folded")]


@pytest.mark.parametrize(
    ("text", "value"),
    [
        (r'a: "\x41\u00e9\U0001F600\t\\\"\/\ \_"', 'A\u00e9\U0001f600\t\\"/ \xa0'),
        (r'a: "\0\a\b\v\f\r\e\N\L\P\n"', "\0\a\b\v\f\r\x1b\x85\u2028\u2029\n"),
        ('a: "tab\\\tx"', "tab\tx"),
        ('a: "one\n  two\n\n  three"', "one two\nthree"),
        ('a: "keep \\\n    joined"', "keep joined"),
        ('a: "a\\\n\n  b"', "a\nb"),
        ('a: "x\\t  \n  y"', "x\t y"),
        ("a: 'it''s'", "it's"),
        ("a: 'one  \n   two'", "one two"),
        ("a: 'x''\n  y'", "x' y"),
        ("a: ''", ""),
        ('a: ""', ""),
    ],
)
def test_quoted_scalars_unescape_and_fold(yp: ModuleType, text: str, value: str) -> None:
    assert value_at(yp, text, ("a",)) == value


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("a: one\n  two\n\n  three\n", "one two\nthree"),
        ("- a\n  - b\n", "a - b"),
        ("a: x  \n   y  # c\n", "x y"),
        ("a: k:v", "k:v"),
        ("a: -1", "-1"),
        ("a: ?x", "?x"),
        ("a: :x", ":x"),
        ("a: x\t", "x"),
    ],
)
def test_plain_scalars_fold_over_deeper_lines(yp: ModuleType, text: str, value: str) -> None:
    path = (0,) if text.startswith("-") else ("a",)
    assert value_at(yp, text, path) == value


def test_flow_plain_scalars_fold_and_stop_at_indicators(yp: ModuleType) -> None:
    assert value_at(yp, "a: [x\n  y]", ("a", 0)) == "x y"
    found = yp.scan("[x\n  y, a:b, c\t, {k: v}\n# comment\n]")
    assert [n.value for n in found if n.kind == "plain"] == ["x y", "a:b", "c", "v"]


def test_a_plain_scalar_does_not_continue_past_a_comment_or_a_shallower_line(yp: ModuleType) -> None:
    found = yp.scan("a: x\n# comment\nb: y\n  z\nc: w\n")
    assert [(n.path, n.value) for n in found if n.kind == "plain"] == [(("a",), "x"), (("b",), "y z"), (("c",), "w")]

"""chock_scan.yamlpath refusals: every input it cannot read with certainty raises ParseError with its line."""

from __future__ import annotations

from types import ModuleType

import pytest

REFUSED = [
    # (text, line, reason pattern)
    ("a:\n\tb: 1\n", 2, "a tab in indentation"),
    ("a:\n  \tb: 1\n", 2, "a tab in indentation"),
    ("a: x\ty\n", 1, "a tab inside a plain scalar"),
    ("k\t: v\n", 1, r"unexpected ':'"),
    ("[a\tb]", 1, "a tab inside a plain scalar"),
    ("? key\n: value\n", 1, r"unexpected '\?'"),
    ("{? a: b}", 1, r"unexpected '\?'"),
    ("[?a]", 1, r"unexpected '\?'"),
    ("{:a: b}", 1, r"unexpected ':'"),
    ("- &a k: v\n", 1, "a tag or anchor on the line where a block collection starts"),
    ("!t k: v\n", 1, "a tag or anchor on the line where a block collection starts"),
    ("- !t - x\n", 1, "a tag or anchor on the line where a block collection starts"),
    ("[a: b]", 1, r"a key: value pair inside \[ \] is not supported"),
    ("{[a]: b}", 1, r"a flow mapping key starting with '\['"),
    ("{*a: b}", 1, r"a flow mapping key starting with '\*'"),
    ("{&a k: b}", 1, r"a flow mapping key starting with '&'"),
    ('{"a\n b": c}', 1, "a flow mapping key spanning lines"),
    ("a: 1\x85b: 2", 1, "character U\\+0085 is not allowed"),
    ("a: 1\nb: \u2028", 2, "character U\\+2028 is not allowed"),
    ("a: \u2029", 1, "character U\\+2029 is not allowed"),
    ("a: \x00", 1, "character U\\+0000 is not allowed"),
    ("a: \x7f", 1, "character U\\+007F is not allowed"),
    ("a: \x1b", 1, "character U\\+001B is not allowed"),
    ("a: 1\n\nb: x\ufeff", 3, "character U\\+FEFF is not allowed"),
    ("a: \ufffe", 1, "character U\\+FFFE is not allowed"),
    ("a: \ud800", 1, "character U\\+D800 is not allowed"),
    ('a: "x\nb: 1\n', 1, "an unterminated quoted scalar"),
    ("a: 'x''", 1, "an unterminated quoted scalar"),
    ('a: "x\n---\nb: 1"\n', 1, "an unterminated quoted scalar"),
    ('a: "x\\', 1, "an invalid escape"),
    (r'a: "\q"', 1, r"an invalid escape \\q"),
    (r'a: "\x4"', 1, r"an invalid escape \\x"),
    (r'a: "\u00g0"', 1, r"an invalid escape \\u"),
    (r'a: "\ud800"', 1, r"an escape that is not a character: \\ud800"),
    (r'a: "\U00110000"', 1, r"an escape that is not a character"),
    ("a: [x, y\n", 2, "an unterminated flow collection"),
    ("a: {x: y", 1, "an unterminated flow collection"),
    ("a: [x, {y: z]", 1, r"expected , or \}, not '\]'"),
    ("a: [x y: z]", 1, r"a key: value pair inside \[ \]"),
    ("a: [x, , y]", 1, "an empty entry in a flow sequence"),
    ("a: [, y]", 1, "an empty entry in a flow sequence"),
    ("a: {x: y z: w}", 1, r"expected , or \}, not ':'"),
    ("a: ['x' 'y']", 1, r"expected , or \], not \"'\""),
    ("[a, &x]", 1, "an empty entry in a flow sequence"),
    ("a: [x]]", 1, r"unexpected '\]'"),
    ("%YAML 1.2\na: 1\n", 1, "a directive must be followed by ---"),
    ("%YAML 1.2\n", 1, "a directive must be followed by ---"),
    ("a: 1\n... junk\n", 2, r"only a comment may follow \.\.\."),
    ("a: 1\n...# not a marker\n", 2, "expected a mapping key"),
    ("a: 1\n b: 2\n", 2, r"unexpected ':'"),
    ("a:\n  b: 1\n c: 2\n", 3, "a mapping entry indented deeper than its siblings"),
    ("- - a\n - b\n", 2, "a sequence entry indented deeper than its siblings"),
    (" a: 1\nb: 2\n", 2, "content after the document's root node"),
    ("a: 1\n- b\n", 2, "expected a mapping key"),
    ("a: 1\nplain\n", 2, "expected a mapping key"),
    ("- a\nb: 1\n", 2, "content after the document's root node"),
    ("a: b: c\n", 1, "a block collection cannot start on the line of its key"),
    ("a: - b\n", 1, "a block collection cannot start on the line of its key"),
    ("a: x\n  b: y\n", 2, r"unexpected ':'"),
    ('a: "x" y\n', 1, r"unexpected 'y'"),
    ('a: "x"# c\n', 1, r"unexpected '#'"),
    ("a: @x\n", 1, r"unexpected '@'"),
    ("a: `x\n", 1, r"unexpected '`'"),
    ("a: %x\n", 1, r"unexpected '%'"),
    ("a: ,x\n", 1, r"unexpected ','"),
    ("a: !t !u x\n", 1, "a second tag on one node"),
    ("a: &x &y x\n", 1, "a second anchor on one node"),
    ("a: !t\n  !u x\n", 2, "a second tag or anchor on one node"),
    ("a: &x\n  &y x\n", 2, "a second tag or anchor on one node"),
    ("a: !t,u x\n", 1, r"unexpected ',' after a tag or anchor"),
    ("[!t,u]", 1, r"unexpected ',' after a tag or anchor"),
    ("a: !t\u00e9 x\n", 1, r"unexpected '\u00e9' after a tag or anchor"),
    ("a: !e!x y\n", 1, r"unexpected '!' after a tag or anchor"),
    ("a: !! x\n", 1, "a tag with a character outside YAML's tag alphabet"),
    ("a: !<x y\n", 1, "a tag with a character outside YAML's tag alphabet"),
    ("a: !%4 x\n", 1, "a tag with a character outside YAML's tag alphabet"),
    ("a: &a.b x\n", 1, "an anchor or alias name other than letters"),
    ("a: & x\n", 1, "an anchor or alias name other than letters"),
    ("a: *\n", 1, "an anchor or alias name other than letters"),
    ("a: *x:y\n", 1, "an anchor or alias name other than letters"),
    ("a: &x *y\n", 1, "an alias cannot carry a tag or anchor"),
    ("*x : v\n", 1, r"unexpected ':'"),
    ("a: |x\n  y\n", 1, r"unexpected 'x'"),
    ("a: |0\n  y\n", 1, r"unexpected '0'"),
    ("a: |++\n  y\n", 1, r"unexpected '\+'"),
    ("a: |#c\n  y\n", 1, r"unexpected '#'"),
    ("a: |\n    \n  y\n", 3, "a leading empty line indented more than the first line of text"),
    ("a: |2\n y\n", 2, "a mapping entry indented deeper than its siblings"),
    ("--- |\ntext\n", 2, "content after the document's root node"),
    ("a: |\n  x\n\ty\n", 3, "a tab in indentation"),
]


@pytest.mark.parametrize(("text", "line", "reason"), REFUSED, ids=[repr(r[0])[:40] for r in REFUSED])
def test_unreadable_input_is_refused_with_its_line(yp: ModuleType, text: str, line: int, reason: str) -> None:
    with pytest.raises(yp.ParseError, match=f"^line {line}: ({reason})") as caught:
        yp.scan(text)
    assert caught.value.line == line
    assert caught.value.reason == str(caught.value).split(": ", 1)[1]
    assert isinstance(caught.value, ValueError)


def test_the_size_limit_is_inclusive_and_counts_characters(yp: ModuleType) -> None:
    assert yp.scan("a: " + "x" * 7, max_chars=10)[1].value == "x" * 7
    with pytest.raises(yp.ParseError, match=r"^line 1: larger than 10 characters$"):
        yp.scan("a: " + "x" * 8, max_chars=10)
    assert yp.MAX_CHARS == 1 << 20
    yp.scan("a: " + "x" * (yp.MAX_CHARS - 3))
    with pytest.raises(yp.ParseError, match="larger than 1048576 characters"):
        yp.scan("a: " + "x" * (yp.MAX_CHARS - 2))


@pytest.mark.parametrize(
    "text",
    ["[" * 5 + "]" * 5, "a:\n b:\n  c:\n   d:\n    e: 1\n", "- - - - - x\n", "a: [{b: [{c: d}]}]", "- {a: [b]}"],
)
def test_the_depth_limit_counts_every_collection(yp: ModuleType, text: str) -> None:
    depth = max(len(n.path) for n in yp.scan(text) if n.kind in ("map", "seq")) + 1
    yp.scan(text, max_depth=depth)
    with pytest.raises(yp.ParseError, match=f"nested deeper than {depth - 1}$"):
        yp.scan(text, max_depth=depth - 1)
    assert yp.MAX_DEPTH == 64


def test_the_node_limit_counts_every_node_across_documents(yp: ModuleType) -> None:
    text = "a: 1\n---\n- b\n- c\n"
    assert len(yp.scan(text, max_nodes=5)) == 5
    with pytest.raises(yp.ParseError, match=r"^line 4: more than 4 nodes$"):
        yp.scan(text, max_nodes=4)
    assert yp.MAX_NODES == 200_000


@pytest.mark.parametrize("text", [b"a: 1", None, 1])
def test_only_text_is_scanned(yp: ModuleType, text: object) -> None:
    with pytest.raises(TypeError, match="text must be str"):
        yp.scan(text)

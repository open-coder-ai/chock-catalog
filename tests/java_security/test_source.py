"""The lexer quality rules read through: comments and literal contents blanked, lines and columns kept."""

from __future__ import annotations

import pytest
from chock_security.decision import FileText
from chock_security.source import blank, code

CASES = [
    ("a == b; // x == y\n", "a == b;          \n"),
    ('s = "a == b";\n', 's = "      ";\n'),
    ('s = "q\\"x";\n', 's = "    ";\n'),
    ("c = '\"';\n", "c = ' ';\n"),
    ("c = '\\n';\n", "c = '  ';\n"),
    ("/* a\n b */ x\n", "    \n      x\n"),
    ('t = """\n  x == y \\"""\n  """;\n', 't = """\n             \n  """;\n'),
    ('t = """\nline\\\nnext""";\n', 't = """\n     \n    """;\n'),
    ('s = "open\nnext == 1\n', 's = "    \nnext == 1\n'),
    ('s = "trail\\\n', 's = "      \n'),
    ("x / y; // end", "x / y;       "),
]


@pytest.mark.parametrize(("raw", "expected"), CASES)
def test_blank_keeps_code_and_blanks_the_rest(raw: str, expected: str) -> None:
    assert blank(raw) == expected
    assert len(blank(raw)) == len(raw)


def test_code_lines_align_with_the_file_lines() -> None:
    text = FileText("A.java", 'int a = 1; /* one\n two */ String s = "x";\n')
    assert code(text) == ["int a = 1;       ", '        String s = " ";']
    assert len(code(text)) == len(text.lines)


ESCAPES = [
    ("a; \\u002f\\u002f b\n", "a;" + " " * 15 + "\n"),
    ("// a \\u000a b; // c\n", " " * 12 + "b;     \n"),
    ("// a \\u000d b\n", " " * 12 + "b\n"),
    ('s = "\\u0022; x;\n', 's = ""     ; x;\n'),
    ('s = "\\\\u0022"; x;\n', 's = "       "; x;\n'),
    ("f\\uuu0028x);\n", "f(       x);\n"),
    ("f(\\u2028);\n", "f(      );\n"),
    ("s = '\\u005c''; x;\n", "s = '       '; x;\n"),
    ("\\uZZZZ;\n", "\\uZZZZ;\n"),
]


@pytest.mark.parametrize(("raw", "expected"), ESCAPES)
def test_unicode_escapes_are_decoded_before_lexing_and_keep_their_columns(raw: str, expected: str) -> None:
    assert blank(raw) == expected
    assert len(blank(raw)) == len(raw)


def test_an_escaped_line_break_keeps_the_file_line_count() -> None:
    text = FileText("A.java", "// a \\u000a int b;\nint c;\n")
    assert code(text) == [" " * 12 + "int b;", "int c;"]

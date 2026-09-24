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

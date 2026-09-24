"""Java and Kotlin source as a rule should read it: code only, comments and literal contents blanked.

A quality rule matching `==` or `catch (` against raw text fires inside a comment, a Javadoc
example or a string literal, and a guard that refuses a comment is noise. `code()` returns the
file line for line -- the same count, so a finding's line number is the author's -- with every
comment replaced by spaces and every string, text block and char literal kept as its quotes
around blanks: `"a == b"` reads as `"      "`. Columns are preserved too.
"""

from __future__ import annotations

from chock_security.decision import FileText

_CODE, _LINE_COMMENT, _BLOCK_COMMENT, _STRING, _TEXT_BLOCK, _CHAR = range(6)


def _blank(ch: str) -> str:
    return ch if ch == "\n" else " "


def _in_code(text: str, i: int) -> tuple[str, int, int]:
    opener = {"//": _LINE_COMMENT, "/*": _BLOCK_COMMENT}.get(text[i : i + 2])
    if opener is not None:
        return "  ", 2, opener
    if text.startswith('"""', i):
        return '"""', 3, _TEXT_BLOCK
    quote = {'"': _STRING, "'": _CHAR}.get(text[i])
    return text[i], 1, _CODE if quote is None else quote


def _in_line_comment(text: str, i: int) -> tuple[str, int, int]:
    return _blank(text[i]), 1, _CODE if text[i] == "\n" else _LINE_COMMENT


def _in_block_comment(text: str, i: int) -> tuple[str, int, int]:
    return ("  ", 2, _CODE) if text[i : i + 2] == "*/" else (_blank(text[i]), 1, _BLOCK_COMMENT)


def _in_text_block(text: str, i: int) -> tuple[str, int, int]:
    if text.startswith('"""', i):
        return '"""', 3, _CODE
    escaped = text[i] == "\\" and text[i : i + 2] != "\\\n"
    return ("  ", 2, _TEXT_BLOCK) if escaped else (_blank(text[i]), 1, _TEXT_BLOCK)


def _in_literal(text: str, i: int, state: int) -> tuple[str, int, int]:
    """A string or char literal: an escape consumes its next character, and a newline ends an
    unterminated one (the compiler rejects it; the rule should still read the next line)."""
    ch = text[i]
    if ch == "\\" and i + 1 < len(text) and text[i + 1] != "\n":
        return "  ", 2, state
    if ch in ('"' if state == _STRING else "'", "\n"):
        return ch, 1, _CODE
    return " ", 1, state


_STEPS = {
    _CODE: _in_code,
    _LINE_COMMENT: _in_line_comment,
    _BLOCK_COMMENT: _in_block_comment,
    _TEXT_BLOCK: _in_text_block,
}


def _step(text: str, i: int, state: int) -> tuple[str, int, int]:
    """(what to emit for text[i:i+n], n, next state) for one lexical step."""
    step = _STEPS.get(state)
    return step(text, i) if step is not None else _in_literal(text, i, state)


def blank(text: str) -> str:
    """`text` with comments and literal contents blanked, newlines and columns kept."""
    out: list[str] = []
    i, state = 0, _CODE
    while i < len(text):
        emitted, width, state = _step(text, i, state)
        out.append(emitted)
        i += width
    return "".join(out)


def code(text: FileText) -> list[str]:
    """The file's lines as code: `text.lines[n]` and `code(text)[n]` are the same line."""
    return blank(text.text).splitlines()

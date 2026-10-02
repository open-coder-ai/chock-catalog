"""Java and Kotlin source as a rule should read it: code only, comments and literal contents blanked.

A quality rule matching `==` or `catch (` against raw text fires inside a comment, a Javadoc
example or a string literal, and a guard that refuses a comment is noise. `code()` returns the
file line for line -- the same count, so a finding's line number is the author's -- with every
comment replaced by spaces and every string, text block and char literal kept as its quotes
around blanks: `"a == b"` reads as `"      "`. Columns are preserved too.

javac decodes `\\uXXXX` escapes before it tokenizes, so the lexer does too: `\\u002f\\u002f` opens a
comment and `\\u000a` ends one. A decoded character keeps its escape's columns (the character, then
blanks), and a decoded line break or other space reads as a blank, so the line count is unchanged.
"""

from __future__ import annotations

import re
from functools import lru_cache

from chock_security.decision import FileText

#: One gate run reads each written file through dozens of rules, and the flow model blanks each body
#: line it tests. Lexing is pure -- the same text always blanks the same way -- so it runs once per
#: distinct text. Bounded, so a long test session or a large commit cannot grow it without limit.
_CACHE_SIZE = 4096

_CODE, _LINE_COMMENT, _BLOCK_COMMENT, _STRING, _TEXT_BLOCK, _CHAR = range(6)


#: What `str.splitlines` ends a line at, beside `\n` and `\r\n`: a vertical tab, form feed, the file,
#: group and record separators, NEL, and U+2028 / U+2029. javac ends a line only at CR and LF, but
#: `FileText.lines` splits on all of these, so blanking keeps each: the count then matches in
#: comments and literals too, and a `//` comment still runs past one, as it does for javac.
_BREAKS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")


#: javac's line terminators: a line comment and an unterminated literal end at either.
_EOL = "\r\n"


def _blank(ch: str) -> str:
    return ch if ch in _BREAKS else " "


def _in_code(text: str, i: int) -> tuple[str, int, int]:
    opener = {"//": _LINE_COMMENT, "/*": _BLOCK_COMMENT}.get(text[i : i + 2])
    if opener is not None:
        return "  ", 2, opener
    if text.startswith('"""', i):
        return '"""', 3, _TEXT_BLOCK
    quote = {'"': _STRING, "'": _CHAR}.get(text[i])
    return text[i], 1, _CODE if quote is None else quote


def _in_line_comment(text: str, i: int) -> tuple[str, int, int]:
    return _blank(text[i]), 1, _CODE if text[i] in _EOL else _LINE_COMMENT


def _in_block_comment(text: str, i: int) -> tuple[str, int, int]:
    return ("  ", 2, _CODE) if text[i : i + 2] == "*/" else (_blank(text[i]), 1, _BLOCK_COMMENT)


def _in_text_block(text: str, i: int) -> tuple[str, int, int]:
    if text.startswith('"""', i):
        return '"""', 3, _CODE
    escaped = text[i] == "\\" and text[i : i + 2] != "\\\n"
    return (" " + _blank(text[i + 1]), 2, _TEXT_BLOCK) if escaped else (_blank(text[i]), 1, _TEXT_BLOCK)


def _in_literal(text: str, i: int, state: int) -> tuple[str, int, int]:
    """A string or char literal: an escape consumes its next character, and a newline ends an
    unterminated one (the compiler rejects it; the rule should still read the next line)."""
    ch = text[i]
    if ch == "\\" and i + 1 < len(text) and text[i + 1] not in _EOL:
        return " " + _blank(text[i + 1]), 2, state
    if ch == ('"' if state == _STRING else "'") or ch in _EOL:
        return ch, 1, _CODE
    return _blank(ch), 1, state


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


def _lex(text: str) -> str:
    out: list[str] = []
    i, state = 0, _CODE
    while i < len(text):
        emitted, width, state = _step(text, i, state)
        out.append(emitted)
        i += width
    return "".join(out)


#: A run of backslashes, then `u`s and four hex digits: an escape when the run's length is odd.
_ESCAPE = re.compile(r"(\\+)u+([0-9A-Fa-f]{4})")


def _decoded(text: str) -> tuple[str, list[int]]:
    """`text` with its Unicode escapes decoded, and the width in `text` of each decoded character."""
    chars: list[str] = []
    widths: list[int] = []
    last = 0
    for match in _ESCAPE.finditer(text):
        if len(match.group(1)) % 2 == 0:
            continue
        start = match.end(1) - 1
        chars.extend(text[last:start])
        widths.extend([1] * (start - last))
        char = chr(int(match.group(2), 16))
        chars.append("\n" if char == "\r" else char)
        widths.append(match.end() - start)
        last = match.end()
    chars.extend(text[last:])
    widths.extend([1] * (len(text) - last))
    return "".join(chars), widths


@lru_cache(maxsize=_CACHE_SIZE)
def blank(text: str) -> str:
    """`text` with comments and literal contents blanked, newlines and columns kept.

    Cached: a pure function of its argument, and the hottest call in the engine."""
    if "\\u" not in text:
        return _lex(text)
    decoded, widths = _decoded(text)
    out: list[str] = []
    for emitted, width in zip(_lex(decoded), widths, strict=True):
        out.append(emitted if width == 1 else (" " if emitted.isspace() else emitted) + " " * (width - 1))
    return "".join(out)


@lru_cache(maxsize=_CACHE_SIZE)
def _code_lines(text: str) -> tuple[str, ...]:
    return tuple(blank(text).splitlines())


def code(text: FileText) -> list[str]:
    """The file's lines as code: `text.lines[n]` and `code(text)[n]` are the same line.

    A fresh list each call, over a cached parse, so no rule can change what the next one reads."""
    return list(_code_lines(text.text))

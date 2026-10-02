"""Mark what a shell expands before the command is parsed, so a name keeps only the text it would literally hold.

A `$` or backtick the shell expands (unquoted or in double quotes, not escaped) becomes EXPANDED, so `"${OUT}/x"`
is never read as substitution syntax, while one it keeps (single-quoted, escaped, or spliced from quoted pieces
such as `a$\\(id\\)` or `"a$"'(id)'`) stays and is judged. `$'...'` is decoded as bash does and re-quoted, so
`$'a\\x3bb'` is judged as `a;b`. Stdlib only.
"""

from __future__ import annotations

import re
import sys

EXPANDED = chr(0xE000)  # a private-use character standing in for an expanded `$` or backtick
REPLACEMENT = chr(0xFFFD)  # what bash prints for a code point past Unicode
_STARTS = frozenset("{(@*#?$!-_")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b", "E": "\x1b"}
_ANSI = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|c.|.)", re.DOTALL)
_COMMENT_AFTER = frozenset(" \t\n;&|(")


def _ansi_char(match: re.Match[str]) -> str:
    code = match.group(1)
    if code[0] in "xuU":
        number = int(code[1:], 16)
        return chr(number) if number <= sys.maxunicode else REPLACEMENT
    if code[0].isdigit():
        return chr(int(code, 8))
    if code[0] == "c" and code[1:]:
        return chr(ord(code[1]) & 0x1F)
    return _ESCAPES.get(code, code)


def _ansi(raw: str, start: int) -> tuple[str, int]:
    """A `$'...'` body beginning at `start`, decoded and single-quoted; and the index after its closing quote."""
    end = start
    while end < len(raw) and raw[end] != "'":
        end += 2 if raw[end] == "\\" else 1
    text = _ANSI.sub(_ansi_char, raw[start:end])
    return "'" + text.replace("'", "'\\''") + "'", end + 1


def _dollar(raw: str, at: int, quote: str, *, powershell: bool) -> tuple[str, int]:
    """What a `$` at `at` becomes, and the index after what it consumed."""
    nxt = raw[at + 1 : at + 2]
    if not powershell and not quote and nxt == "'":
        return _ansi(raw, at + 2)
    if not powershell and not quote and nxt == '"':
        return "", at + 1  # $"..." is a translated string: the `$` goes, the string stays
    expands = bool(nxt) and (nxt.isalnum() or nxt in _STARTS)
    return (EXPANDED if expands else "$"), at + 1


def mark_expansions(raw: str, *, powershell: bool) -> str:
    """The command line with every expanded `$` or backtick replaced by EXPANDED and every `$'...'` decoded."""
    out: list[str] = []
    quote, i = "", 0
    escape = "`" if powershell else "\\"
    while i < len(raw):
        char = raw[i]
        if quote == "'":
            quote = "" if char == "'" else quote
            out.append(char)
            i += 1
        elif char == escape:
            out.append(raw[i : i + 2])
            i += 2
        elif char == "#" and not quote and (i == 0 or raw[i - 1] in _COMMENT_AFTER):
            end = raw.find("\n", i)
            end = len(raw) if end < 0 else end
            out.append(raw[i:end])
            i = end
        elif char == "$":
            text, i = _dollar(raw, i, quote, powershell=powershell)
            out.append(text)
        elif char == "`" and quote == '"':
            out.append(EXPANDED)
            i += 1
        else:
            if char in "'\"" and quote in ("", char):
                quote = "" if quote else char
            out.append(char)
            i += 1
    return "".join(out)

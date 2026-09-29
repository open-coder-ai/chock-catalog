"""JavaScript and TypeScript as a rule should read it: comments removed, and optionally string contents.

There is no parser here, so a rule matching text against raw source fires inside a comment or a
string. `strip_comments` returns the file line for line -- same count, same columns -- with every
comment replaced by spaces and every string kept; `shape` also blanks what is inside strings and
template literals, so `"env: process.env"` in a message reads as `"                "`.
"""

from __future__ import annotations

from functools import lru_cache

_CACHE_SIZE = 256
_QUOTES = "\"'`"


def _blank(ch: str) -> str:
    return ch if ch == "\n" else " "


def _skip_comment(text: str, i: int) -> tuple[str, int]:
    """The blanked comment starting at `i`, and where it ends."""
    if text.startswith("//", i):
        end = text.find("\n", i)
        end = len(text) if end < 0 else end
    else:
        end = text.find("*/", i + 2)
        end = len(text) if end < 0 else end + 2
    return "".join(_blank(c) for c in text[i:end]), end


def _string(text: str, i: int, *, keep: bool) -> tuple[str, int]:
    """A quoted literal starting at `i`: its text (or blanks inside its quotes), and where it ends."""
    quote = text[i]
    j = i + 1
    while j < len(text) and text[j] != quote and not (text[j] == "\n" and quote != "`"):
        j += 2 if text[j] == "\\" else 1
    j = min(j, len(text))
    body = text[i + 1 : j]
    inner = body if keep else "".join(_blank(c) for c in body)
    closing = text[j : j + 1] if text[j : j + 1] == quote else ""
    return quote + inner + closing, min(j + len(closing), len(text))


def _lex(text: str, *, keep: bool) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith(("//", "/*"), i):
            piece, i = _skip_comment(text, i)
        elif text[i] in _QUOTES:
            piece, i = _string(text, i, keep=keep)
        else:
            piece, i = text[i], i + 1
        out.append(piece)
    return "".join(out)


@lru_cache(maxsize=_CACHE_SIZE)
def strip_comments(text: str) -> str:
    """The file with comments blanked and strings intact."""
    return _lex(text, keep=True)


@lru_cache(maxsize=_CACHE_SIZE)
def shape(text: str) -> str:
    """The file with comments blanked and every string's contents blanked."""
    return _lex(text, keep=False)

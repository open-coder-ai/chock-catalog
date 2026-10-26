"""JSON with comments and trailing commas, read from the original text the way the clients that accept it do.

The text is never split into lines and joined again: a raw U+2028 inside a string is data, not a line end.
A `//` comment ends at any character a client may treat as a line end, so text a client could read as live is
read here too, and fails closed when it is not JSON.
"""

from __future__ import annotations

import json
from typing import Any

_LINE_ENDS = "\n\r\u2028\u2029\x85"


def _strip(text: str) -> str:
    """The text without comments; a string's content, comment markers included, is kept as written."""
    out: list[str] = []
    i, n, in_string = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
            i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            i = next((j for j in range(i, n) if text[j] in _LINE_ENDS), n)
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                msg = "an unterminated comment"
                raise ValueError(msg)
            out.append(" ")
            i = end + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _drop_trailing_commas(text: str) -> str:
    """A comma followed only by whitespace and a closing bracket is dropped; one inside a string never is."""
    out: list[str] = []
    i, n, in_string = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if not (j < n and text[j] in "}]"):
                out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def loads(text: str) -> Any:
    """The value of a JSONC text; ValueError (RecursionError for absurd nesting) when it is not one."""
    return json.loads(_drop_trailing_commas(_strip(text)))

"""JSON5 to JSON-with-comments text, so the shared JSONC reader parses it: unquoted (and escaped) keys are
quoted, single-quoted strings become double-quoted, line continuations inside strings are joined. Comments
and trailing commas are left for the JSONC reader. Anything else JSON5 allows and JSON does not (hex or
signed numbers, Infinity, NaN) is left as written, so the JSONC reader refuses it: never guessed.
"""

from __future__ import annotations

import json
import re

IDENT = re.compile(r"(?:[A-Za-z_$]|\\u[0-9A-Fa-f]{4})(?:[\w$]|\\u[0-9A-Fa-f]{4})*")
ESCAPE = re.compile(r"\\u([0-9A-Fa-f]{4})")
SPACE = re.compile(r"\s*")
LINE_BREAKS = "\r\n\u2028\u2029"
LINE_END = re.compile("[\r\n\u2028\u2029]")


class Json5Error(ValueError):
    pass


def _string(text: str, start: int, out: list[str]) -> int:
    """Copy the string opened at `start` as a double-quoted JSON string; the offset after its closing quote."""
    quote, index = text[start], start + 1
    out.append('"')
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            following = text[index + 1]
            if following in LINE_BREAKS:
                index += 3 if text.startswith("\r\n", index + 1) else 2
                continue
            out.append(following if following == "'" else char + following)
            index += 2
            continue
        if char == quote:
            out.append('"')
            return index + 1
        if char in LINE_BREAKS:
            break
        out.append('\\"' if char == '"' else char)
        index += 1
    msg = "an unclosed string"
    raise Json5Error(msg)


def _comment(text: str, start: int, out: list[str]) -> int:
    """Copy the comment at `start` unchanged (the JSONC reader drops it); the offset after it."""
    if text.startswith("/*", start):
        end = text.find("*/", start + 2)
        end = len(text) if end < 0 else end + 2
        out.append(text[start:end])
        return end
    # A line comment ends at any JSON5 line terminator; the JSONC reader takes only LF or CRLF as the end of
    # one, so a lone CR, LS or PS that ends it is written as LF.
    found = LINE_END.search(text, start)
    end = found.start() if found else len(text)
    out.append(text[start:end])
    if found and not text.startswith(("\n", "\r\n"), end):
        out.append("\n")
        return end + 1
    return end


def to_jsonc(text: str) -> str:
    """The JSON5 text as JSON with comments; Json5Error for an unclosed string."""
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in "\"'":
            index = _string(text, index, out)
        elif text.startswith(("//", "/*"), index):
            index = _comment(text, index, out)
        elif (match := IDENT.match(text, index)) and text.startswith(":", SPACE.match(text, match.end()).end()):
            out.append(json.dumps(ESCAPE.sub(lambda m: chr(int(m[1], 16)), match[0])))
            index = match.end()
        elif match:
            out.append(match[0])
            index = match.end()
        else:
            out.append(char)
            index += 1
    return "".join(out)

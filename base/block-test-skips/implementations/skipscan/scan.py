"""Bracket and string scanning shared by the runner-config and JavaScript rules."""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable

QUOTES = "'\"`"
PAIRS = {"(": ")", "[": "]", "{": "}"}


#: Line breaks as Python's own reader counts them, and as JS and C# count them (LS and PS too).
PY_BREAK = re.compile(r"\r\n|[\r\n]")
ANY_BREAK = re.compile(r"\r\n|[\r\n\u2028\u2029]")


def breaks_for(kind: str) -> re.Pattern[str]:
    return PY_BREAK if kind in ("python", "pytest-config") else ANY_BREAK


def split_lines(text: str, breaks: re.Pattern[str] = ANY_BREAK) -> list[str]:
    """The text's lines, split where its language breaks them: hit lines and key text then agree."""
    lines = breaks.split(text)
    return lines[:-1] if lines[-1] == "" else lines


def line_index(text: str, breaks: re.Pattern[str] = ANY_BREAK) -> Callable[[int], int]:
    """Offset -> 1-based line number, from one pass over the text."""
    ends = [found.end() for found in breaks.finditer(text)]
    return lambda offset: bisect_right(ends, offset) + 1


#: What may precede a regex literal rather than a division: an operator, an opener, or a line start.
#: Not `<`/`>` (a JSX `</Tag>` is no regex) nor `+`/`-` (`x++ / 2` is division).
REGEX_BEFORE = re.compile(r"(?:^|[(,=:\[!&|?{};*%~^])[ \t]*\Z", re.MULTILINE)


def _regex_end(text: str, start: int) -> int:
    """The index past a regex literal's closing slash, skipping escapes and `[...]` classes; its line ends it."""
    index, in_class = start + 1, False
    while index < len(text) and text[index] not in "\r\n\u2028\u2029":
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "/" and not in_class:
            return index + 1
        in_class = (in_class or char == "[") and char != "]"
        index += 1
    return index + 1


def blank_code(text: str) -> str:
    """Comments and string contents turned to spaces, offsets and breaks kept, so a scan sees code only."""
    out = list(text)
    index = 0
    while index < len(text):
        if text[index] in QUOTES:
            end = _string_end(text, index)
            start, index = index + 1, end
            end -= 1
        elif text.startswith("//", index):
            found = ANY_BREAK.search(text, index)
            start, end = index, found.start() if found else len(text)
            index = end
        elif text.startswith("/*", index):
            close = text.find("*/", index + 2)
            start, end = index, len(text) if close < 0 else close + 2
            index = end
        elif text[index] == "/" and REGEX_BEFORE.search(text, max(0, index - 80), index):
            # A JS regex literal (`/\/*$/`, ``/`/``): its slashes, quotes and backticks are not code either.
            start, end = index + 1, _regex_end(text, index)
            index = end
            end -= 1
        else:
            index += 1
            continue
        out[start:end] = [char if char in "\r\n\u2028\u2029" else " " for char in text[start:end]]
    return "".join(out)


def _string_end(text: str, start: int) -> int:
    """The index just past the string literal opening at `start`; a plain quote ends at its line."""
    quote = text[start]
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote or (char == "\n" and quote != "`"):
            return index + 1
        index += 1
    return len(text)


def closes(code: str) -> dict[int, int]:
    """Open bracket offset -> offset past its matching close, in one pass over blanked code."""
    found: dict[int, int] = {}
    stack: list[tuple[int, str]] = []
    for index, char in enumerate(code):
        if char in PAIRS:
            stack.append((index, PAIRS[char]))
        elif stack and char == stack[-1][1]:
            found[stack.pop()[0]] = index + 1
    return found


def group(text: str, start: int) -> tuple[int, list[tuple[int, str]]]:
    """From the bracket at `start`: the index past its close, and the strings directly inside it.

    Strings are skipped whole, so a bracket inside one does not count. An unclosed group runs to
    the end of the text.
    """
    closers: list[str] = []
    found: list[tuple[int, str]] = []
    index = start
    while index < len(text):
        char = text[index]
        if char in QUOTES:
            end = _string_end(text, index)
            if len(closers) == 1:
                found.append((index, text[index + 1 : end - 1]))
            index = end
            continue
        if char in PAIRS:
            closers.append(PAIRS[char])
        elif closers and char == closers[-1]:
            closers.pop()
            if not closers:
                return index + 1, found
        index += 1
    return len(text), found

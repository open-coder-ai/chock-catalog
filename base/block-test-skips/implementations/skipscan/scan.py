"""Bracket and string scanning shared by the runner-config and JavaScript rules."""

from __future__ import annotations

QUOTES = "'\"`"
PAIRS = {"(": ")", "[": "]", "{": "}"}


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


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

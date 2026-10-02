"""High-entropy values assigned to secret-like keys: keyword_values' candidates, judged by entropy, minus shapes.

A candidate is dropped when entropy allows it (reference, digest, UUID, placeholder, ...) or when
shapes.explain names the non-secret shape it is written in (code, text, a regex, a path).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import NamedTuple

from chock_scan import entropy, keyword_values

from entropyscan import shapes

#: keyword_values refuses text over MAX_CHARS, so text is fed in chunks of whole lines under it; a
#: longer line is fed in windows overlapping by OVERLAP. An assignment spans at most about 530
#: characters before its value (key 130, blanks and operator 34, two tags 336, quote and auth word
#: 25), so a window leaves a value starting HANDOFF or more past its step to the next window, which
#: holds that assignment whole; a value it keeps ends inside it (HANDOFF + 151 < OVERLAP).
CHUNK = keyword_values.MAX_CHARS
OVERLAP = 1024
HANDOFF = 600
LINES = re.compile(r"\r\n|\r|\n")
#: What opens a string literal in source code, up to a value keyword_values reads after an auth word.
_OPENED = re.compile(r"[\"'`](?:(?i:bearer|basic|token|bot)[ \t]{1,16})?\Z")


class Hit(NamedTuple):
    """A suspicious value: its 1-based line, the key it is assigned to, the value, its assessment."""

    line: int
    key: str
    value: str
    assessment: entropy.Assessment


def split_lines(text: str) -> list[str]:
    """Lines as keyword_values counts them: \\n, \\r\\n and \\r alike."""
    return LINES.split(text)


def chunks(lines: list[str]) -> Iterator[tuple[int, str, int | None, int]]:
    """(index of the first line, text, column limit, column offset) pieces under CHUNK characters.

    A line of CHUNK or more comes in overlapping windows, each with its offset in the line; every
    window but the last has a limit, the value column from which the next window takes over.
    Whole-line pieces have neither.
    """
    start, size, group = 0, 0, []
    step = CHUNK - OVERLAP
    for index, line in enumerate(lines):
        if len(line) >= CHUNK:
            if group:
                yield start, "\n".join(group), None, 0
            start, size, group = index + 1, 0, []
            offsets = range(0, len(line) - OVERLAP, step)
            for offset in offsets:
                last = offset == offsets[-1]
                yield index, line[offset : offset + CHUNK], None if last else step + HANDOFF, offset
            continue
        if size + len(line) + 1 > CHUNK:
            yield start, "\n".join(group), None, 0
            start, size, group = index, 0, []
        group.append(line)
        size += len(line) + 1
    if group:
        yield start, "\n".join(group), None, 0


def hits(lines: list[str], *, source_code: bool = False) -> Iterator[Hit]:
    """Each keyword-adjacent value entropy calls suspicious and no shape explains, once per value.

    In source code (`source_code`) a value not opened by a quote is never a string literal (an
    identifier, a number, a comment's text), so only quoted values are judged there.
    """
    seen: set[tuple[int, str]] = set()
    for first, text, limit, offset in chunks(lines):
        for found in keyword_values.candidates(text):
            line = first + found.line
            if (limit is not None and found.column >= limit) or (line, found.value) in seen:
                continue
            start = offset + found.column
            if source_code and not _OPENED.search(lines[line - 1], max(0, start - 24), start):
                continue
            seen.add((line, found.value))
            value = shapes.trim(found.value)
            judged = entropy.assess(value)
            if judged.suspicious and shapes.explain(value, found.key) is None:
                yield Hit(line, found.key, value, judged)

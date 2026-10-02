"""Install- and build-time hook detectors for package-lifecycle-scripts; one module per family of files."""

from __future__ import annotations

from typing import NamedTuple

#: Verdict classes a hit carries: BLOCK for a hook that downloads, decodes or evaluates code (or the
#: structural shapes the roadmap blocks), ASK for any other new or changed hook.
BLOCK, ASK = "block", "ask"


class Hit(NamedTuple):
    """One hook a file declares: where, which rule, what it is (entry), its normalized value, its class."""

    line: int
    rule: str
    entry: str
    value: str
    level: str
    why: str


def norm(text: str) -> str:
    """Whitespace-collapsed text: the value part of a key, so reflowing an old hook keeps it old."""
    return " ".join(str(text).split())


def line_of(text: str, needle: str, start: int = 1) -> int:
    """The 1-based line of the first occurrence of `needle` at or after line `start`, else `start`."""
    lines = text.splitlines()
    for number in range(max(start, 1), len(lines) + 1):
        if needle in lines[number - 1]:
            return number
    return max(start, 1)

"""Install- and build-time hook detectors for package-lifecycle-scripts; one module per family of files."""

from __future__ import annotations

import hashlib
import re
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
    """The value part of a key: line endings unified and outer blank lines dropped, nothing else.

    Inner spaces, newlines and indentation stay: in a shell, Ruby or Python any of them can change
    what runs (a newline separates commands, an indent moves a call out of a block, a trailing
    backslash-space is not a continuation), so normalizing them would let a changed hook keep an old key.
    """
    return re.sub(r"\r\n?", "\n", str(text)).strip("\n")


def digest(text: str) -> str:
    """A short digest of `norm(text)`: the key of a whole file or block, so any meaningful edit is new."""
    return hashlib.sha256(norm(text).encode("utf-8", "replace")).hexdigest()[:16]


def line_of(text: str, needle: str, start: int = 1) -> int:
    """The 1-based line of the first occurrence of `needle` at or after line `start`, else `start`."""
    lines = text.splitlines()
    for number in range(max(start, 1), len(lines) + 1):
        if needle in lines[number - 1]:
            return number
    return max(start, 1)

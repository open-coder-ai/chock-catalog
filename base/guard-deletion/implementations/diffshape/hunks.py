"""Hunks of a change: the lines removed and added in one place, from a -U0 patch or from two texts."""

from __future__ import annotations

import difflib
import re
from collections import Counter
from dataclasses import dataclass

#: Past this many lines in either revision, difflib is too slow; the whole file is one hunk by line counts.
DIFFLIB_LINES = 4000
HEADER = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
ESCAPES = {"t": "\t", "n": "\n", "\\": "\\", '"': '"'}
ESCAPE = re.compile(r"\\([tn\\\"]|[0-7]{3})")


@dataclass(frozen=True)
class Hunk:
    path: str
    line: int
    removed: tuple[str, ...]
    added: tuple[str, ...]
    old: str = ""  # the path before a rename or move, when the patch names one


def lines_of(text: str) -> list[str]:
    """Lines split on newlines only (as git does), each without a trailing carriage return."""
    parts = text.split("\n")
    if parts[-1] == "":
        parts.pop()
    return [p.rstrip("\r") for p in parts]


def from_texts(path: str, old: str, new: str) -> list[Hunk]:
    """The hunks that turn `old` into `new`, one per run of changed lines."""
    before, after = lines_of(old), lines_of(new)
    if max(len(before), len(after)) > DIFFLIB_LINES:
        gone, came = Counter(before) - Counter(after), Counter(after) - Counter(before)
        removed, added = tuple(gone.elements()), tuple(came.elements())
        return [Hunk(path, 1, removed, added)] if removed or added else []
    ops = difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes()
    return [
        Hunk(path, j1 + 1, tuple(before[i1:i2]), tuple(after[j1:j2])) for tag, i1, i2, j1, j2 in ops if tag != "equal"
    ]


def _name(header: str, prefix: str) -> str | None:
    name = header.split("\t", 1)[0]
    if name == "/dev/null":
        return None
    if len(name) > 1 and name.startswith('"') and name.endswith('"'):
        name = ESCAPE.sub(lambda m: ESCAPES.get(m[1]) or chr(int(m[1], 8)), name[1:-1])
    return name.removeprefix(prefix)


class _Reader:
    """State of one patch read: the file being described, the hunk being counted, and the hunks found."""

    def __init__(self) -> None:
        self.hunks: list[Hunk] = []
        self.old = self.new = None
        self.moved = ""
        self.removed: list[str] = []
        self.added: list[str] = []
        self.need_old = self.need_new = 0
        self.start = 1

    def body(self, raw: str) -> None:
        """One line inside a counted hunk; the hunk closes when both counts reach zero."""
        if raw.startswith("-") and self.need_old:
            self.removed.append(raw[1:].rstrip("\r"))
            self.need_old -= 1
        elif raw.startswith("+") and self.need_new:
            self.added.append(raw[1:].rstrip("\r"))
            self.need_new -= 1
        if not self.need_old and not self.need_new:
            path = self.new or self.old or ""
            self.hunks.append(Hunk(path, self.start, tuple(self.removed), tuple(self.added), self.old or ""))

    def header(self, raw: str) -> None:
        """One line outside a hunk: a file header, a rename note or a hunk header."""
        if raw.startswith("diff --git "):
            self.old = self.new = None
        elif raw.startswith("rename from "):
            self.moved = raw[len("rename from ") :]
        elif raw.startswith("rename to ") and self.moved:
            self.hunks.append(Hunk(raw[len("rename to ") :], 1, (), (), self.moved))
            self.moved = ""
        elif raw.startswith("--- "):
            self.old = _name(raw[4:], "a/")
        elif raw.startswith("+++ "):
            self.new = _name(raw[4:], "b/")
        elif match := HEADER.match(raw):
            self.need_old = 1 if match[1] is None else int(match[1])
            self.need_new = 1 if match[3] is None else int(match[3])
            self.start = max(int(match[2]), 1)
            self.removed, self.added = [], []


def parse_patch(text: str) -> list[Hunk]:
    """The hunks of a `git diff -U0 --src-prefix=a/ --dst-prefix=b/` patch, and a note for each rename.

    A hunk header gives its removed and added line counts, so a content line that starts with
    `--- ` or `+++ ` is never mistaken for a file header.
    """
    reader = _Reader()
    for raw in text.split("\n"):
        if reader.need_old or reader.need_new:
            reader.body(raw)
        else:
            reader.header(raw)
    return reader.hunks

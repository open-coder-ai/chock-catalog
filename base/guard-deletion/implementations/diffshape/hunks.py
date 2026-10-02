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


def parse_patch(text: str) -> list[Hunk]:
    """The hunks of a `git diff -U0 --src-prefix=a/ --dst-prefix=b/` patch.

    A hunk header gives its removed and added line counts, so a content line that starts with
    `--- ` or `+++ ` is never mistaken for a file header.
    """
    hunks: list[Hunk] = []
    old_path = new_path = None
    removed: list[str] = []
    added: list[str] = []
    need_old = need_new = 0
    start = 1
    for raw in text.split("\n"):
        if need_old or need_new:
            if raw.startswith("-") and need_old:
                removed.append(raw[1:].rstrip("\r"))
                need_old -= 1
            elif raw.startswith("+") and need_new:
                added.append(raw[1:].rstrip("\r"))
                need_new -= 1
            if not need_old and not need_new:
                hunks.append(Hunk(new_path or old_path or "", start, tuple(removed), tuple(added)))
            continue
        if raw.startswith("diff --git "):
            old_path = new_path = None
        elif raw.startswith("--- "):
            old_path = _name(raw[4:], "a/")
        elif raw.startswith("+++ "):
            new_path = _name(raw[4:], "b/")
        elif match := HEADER.match(raw):
            need_old = 1 if match[1] is None else int(match[1])
            need_new = 1 if match[3] is None else int(match[3])
            start = max(int(match[2]), 1)
            removed, added = [], []
    return hunks

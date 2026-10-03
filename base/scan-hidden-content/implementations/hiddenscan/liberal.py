"""Markdown with the '<' and '>' of everything that may be code removed: the reading for what a renderer escapes.

spans.blank_code blanks only code this reader is certain of, so code it is not certain of is read as text, where
a `-->` or an open quote in it ends or opens what a renderer escapes. This reading takes as code every
fence-like region (to its closing fence, or the end of the file), every indented block after a blank line, and
every pair of backtick runs in a paragraph, as CommonMark pairs them across its lines; the gate reads both.
"""

from __future__ import annotations

import re

from hiddenscan.blocks import CODE_INDENT, _indent

#: A fence after any list or block quote markers; a backtick fence whose info string holds a backtick is not one.
FENCE = re.compile(r"^[ \t>]*(?:(?:[-+*]|\d{1,9}[.)])[ \t>]+)*(`{3,}|~{3,})(.*)$")
TICKS = re.compile(r"(\\*)(`+)")


def _fenced(lines: list[str]) -> list[bool]:
    """Whether each line is in a fence-like region, its fences included."""
    out: list[bool] = []
    run = ""
    for line in lines:
        found = FENCE.match(line)
        if not run:
            if found and not (found.group(1)[0] == "`" and "`" in found.group(2)):
                run = found.group(1)
            out.append(bool(run))
            continue
        out.append(True)
        if found and found.group(1)[0] == run[0] and len(found.group(1)) >= len(run) and not found.group(2).strip():
            run = ""
    return out


def _indented(lines: list[str], fenced: list[bool]) -> list[bool]:
    """Whether each line is in an indented block: indented four or more after a blank line or such a line."""
    out = [False] * len(lines)
    after = True  # after a blank line or an indented code line
    for at, line in enumerate(lines):
        if fenced[at]:
            after = False
        elif not line.strip():
            after = True
        else:
            out[at] = after = _indent(line) >= CODE_INDENT and after
    return out


def _pairs(chunk: str) -> list[tuple[int, int]]:
    """CommonMark's code spans in one paragraph: each backtick run pairs with the next run as long, and a run
    with none is literal."""
    runs = []
    for m in TICKS.finditer(chunk):
        start = m.start(2) + len(m.group(1)) % 2  # a backtick after an odd number of backslashes is literal
        if start < m.end(2):
            runs.append((start, m.end(2)))
    following: dict[int, int] = {}
    after = [-1] * len(runs)
    for k in range(len(runs) - 1, -1, -1):  # the next run of each length, found once: linear
        size = runs[k][1] - runs[k][0]
        after[k] = following.get(size, -1)
        following[size] = k
    out, i = [], 0
    while i < len(runs):
        if (j := after[i]) < 0:
            i += 1
        else:
            out.append((runs[i][0], runs[j][1]))
            i = j + 1
    return out


def view(text: str, tags: str) -> str:
    """The tag view with the '<' and '>' of everything that may be code removed, newlines and length kept."""
    lines = text.split("\n")
    fenced = _fenced(lines)
    code = [f or i for f, i in zip(fenced, _indented(lines, fenced), strict=True)]
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line) + 1)
    spans: list[tuple[int, int]] = [(starts[at], starts[at + 1] - 1) for at in range(len(lines)) if code[at]]
    first = None  # the first line of the paragraph being read
    for at in range(len(lines) + 1):
        if at < len(lines) and not code[at] and lines[at].strip():
            first = at if first is None else first
        elif first is not None:
            spans += [(starts[first] + a, starts[first] + b) for a, b in _pairs(text[starts[first] : starts[at] - 1])]
            first = None
    chars = list(tags)
    for start, end in spans:
        for k in range(start, end):
            if chars[k] in "<>":
                chars[k] = " "
    return "".join(chars)

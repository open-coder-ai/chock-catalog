"""Join the physical lines of a build file into the logical lines a flag is read from."""

from __future__ import annotations

from hardflags.blank import SHELL_KINDS, odd_backslashes

#: Kinds whose lines run on past a backslash; the others run on while a bracket is open.
JOINED = SHELL_KINDS | {"make"}
BRACKETS = {"cmake": "(", "meson": "([{", "toml": "[{", "rust": "([{"}
CLOSERS = {"(": ")", "[": "]", "{": "}"}
MAX_LINES = 64

Logical = tuple[str, list[int]]


def _depth(code_line: str, opens: str) -> int:
    """How many brackets of `opens` the line leaves open, ignoring any inside quotes."""
    depth, quote = 0, ""
    for ch in code_line:
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch in opens:
            depth += 1
        elif ch in (CLOSERS[o] for o in opens):
            depth -= 1
    return depth


def _groups(kind: str, code: list[str], raw: list[str]) -> list[list[int]]:
    """Indexes of the physical lines that make up each logical line."""
    groups: list[list[int]] = []
    current: list[int] = []
    depth = 0
    for i, line in enumerate(code):
        current.append(i)
        if kind in JOINED:
            body = raw[i] if kind == "make" else line
            blank = kind == "docker" and not line.strip() and raw[i].strip().startswith("#")
            more = odd_backslashes(body) or (blank and len(current) > 1)
        elif kind in BRACKETS:
            depth = max(depth + _depth(line, BRACKETS[kind]), 0)
            more = depth > 0
        else:
            more = False
        if more and len(current) < MAX_LINES:
            continue
        groups.append(current)
        current, depth = [], 0
    return groups + ([current] if current else [])


def logical_lines(kind: str, code: str, raw: str, *, bare: bool = False) -> list[Logical]:
    """Each logical line with the physical line number of every character in it.

    A backslash continuation reads as a space, or as nothing when `bare` (a shell joins `a\\<nl>b` to
    `ab`, Make to `a b`); a bracketed span always reads its line ends as spaces.
    """
    code_lines, raw_lines = code.split("\n"), raw.split("\n")
    out: list[Logical] = []
    for group in _groups(kind, code_lines, raw_lines):
        text, owners = "", []
        for n, i in enumerate(group):
            piece = code_lines[i]
            last = n == len(group) - 1
            if kind in JOINED and not last:
                piece = piece.rstrip("\r")
                piece = piece[:-1] if piece.endswith("\\") else piece
                glue = "" if bare else " "
            else:
                piece, glue = piece.rstrip("\r"), ("" if last else " ")
            text += piece + glue
            owners += [i + 1] * (len(piece) + len(glue))
        out.append((text, owners))
    return out

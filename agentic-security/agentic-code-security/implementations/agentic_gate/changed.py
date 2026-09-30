"""Judge only what a change adds: a finding stays when a line it involves is new against the baseline.

A finding involves its own line, the lines its rule recorded for it (a flow's parameter and hops, an MCP
server's whole entry), and the Python statement each of those sits in. A line is new when the written
text holds more copies of it than the baseline does.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Callable, Iterable
from pathlib import Path

from agentic_gate.model import FileText, Finding
from agentic_gate.pyast import tree

#: Where the runner sends the agent's writes, before they land and at the turn's end.
TOOL_USE = "tool_use"

Head = Callable[[str], "str | None"]

#: A statement longer than this is not read as one: the finding's own line stands for it.
_SPAN_LIMIT = 60


def on_disk(root: Path, path: str) -> str | None:
    """The file as it is on disk, or None when it is not there."""
    try:
        return (root / path).read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None


def baseline(root: Path, path: str, after: str, event: str | None, head: Head) -> str | None:
    """What the write replaces; None for a file with no earlier text, so every line of it is new.

    At commit that is HEAD. As the agent writes it is the file on disk; at the turn's end the disk
    already holds `after`, so it is HEAD again.
    """
    if event == TOOL_USE:
        disk = on_disk(root, path)
        if disk is not None and disk != after:
            return disk
    return head(path)


def _key(line: str) -> str:
    """A line as compared: without its indentation or a trailing comma, which appending an entry adds."""
    return line.strip().rstrip(",")


def new_lines(lines: list[str], before: str | None) -> set[int]:
    """1-based numbers of the lines beyond the baseline's copies (indentation, trailing comma ignored)."""
    if before is None:
        return set(range(1, len(lines) + 1))
    left = Counter(_key(line) for line in before.splitlines())
    fresh: set[int] = set()
    for number, line in enumerate(lines, 1):
        key = _key(line)
        if left[key] > 0:
            left[key] -= 1
        else:
            fresh.add(number)
    return fresh


def _extent(node: ast.stmt) -> range:
    """The lines a statement is made of; a compound statement is its header, not its body."""
    first = min([node.lineno, *(d.lineno for d in getattr(node, "decorator_list", ()))])
    body = getattr(node, "body", None)
    last = node.end_lineno or node.lineno
    if isinstance(body, list) and body:
        last = max(node.lineno, body[0].lineno - 1)
    return range(first, last + 1)


def statement(text: FileText, line_no: int) -> range:
    """The lines of the Python statement `line_no` sits in; the line alone for anything else."""
    alone = range(line_no, line_no + 1)
    parsed = tree(text) if text.kind == "python" else None
    if parsed is None:
        return alone
    around = [r for node in ast.walk(parsed) if isinstance(node, ast.stmt) and line_no in (r := _extent(node))]
    span = min(around, key=len, default=alone)
    return span if len(span) <= _SPAN_LIMIT else alone


def involved(finding: Finding, text: FileText) -> set[int]:
    """Every line a finding depends on."""
    lines: set[int] = set()
    for number in (finding.line_no, *finding.related):
        lines.update(statement(text, number))
    return lines


def only_new(findings: Iterable[Finding], text: FileText, before: str | None) -> list[Finding]:
    """The findings with a new line among the lines they involve; a finding that is itself a diff stays."""
    fresh = new_lines(text.lines, before)
    return [f for f in findings if f.by_diff or fresh & involved(f, text)]

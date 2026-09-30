"""The findings document a run prints, so the engine can tell the findings a change adds from old ones.

One finding per hit, keyed by rule id, dotted enclosing class and function names, and the flagged line with
its whitespace collapsed -- never a line number, so an edit that moves a violation does not make it new, and
a deleted guard that creates one does. The engine runs the gate again on the baseline text and blocks the
keys the change holds more of. A finding that is itself a comparison with HEAD is marked `new`.
"""

from __future__ import annotations

import ast
from bisect import bisect_right
from collections.abc import Callable, Iterable, Mapping

from agentic_gate.model import FileText, Finding
from agentic_gate.pyast import tree


def _scopes(text: FileText) -> Callable[[int], str]:
    """The dotted names of the classes and functions a line sits in; '' outside them or in a non-Python file."""
    parsed = tree(text) if text.kind == "python" else None
    defs = [
        (min([n.lineno, *(d.lineno for d in n.decorator_list)]), n.end_lineno or n.lineno, n.name)
        for n in (ast.walk(parsed) if parsed else ())
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
    ]
    defs.sort(key=lambda d: (d[0], -d[1]))
    starts = [start for start, _, _ in defs]

    def scope(line_no: int) -> str:
        around = [d for d in defs[: bisect_right(starts, line_no)] if line_no <= d[1]]
        return ".".join(name for _, _, name in around)

    return scope


def key(finding: Finding, scope: str) -> str:
    """rule id | dotted enclosing scope | flagged line, whitespace collapsed."""
    return f"{finding.rule_id}|{scope}|{' '.join(finding.line.split())}"


def document(findings: Iterable[Finding], writes: Mapping[str, str]) -> dict[str, list[dict[str, object]]]:
    """The `{"findings": [...]}` the engine compares against the baseline run's."""
    scopes: dict[str, Callable[[int], str]] = {}
    rows: list[dict[str, object]] = []
    for finding in findings:
        scope = scopes.setdefault(finding.path, _scopes(FileText(finding.path, writes[finding.path])))
        row: dict[str, object] = {
            "key": key(finding, scope(finding.line_no)),
            "path": finding.path,
            "line": finding.line_no,
            "message": finding.summary(),
        }
        if finding.by_diff:
            row["new"] = True
        rows.append(row)
    return {"findings": rows}

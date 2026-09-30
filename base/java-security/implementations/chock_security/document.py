"""The findings document a run prints, so the engine can tell the findings a change adds from old ones.

The gate prints one finding per refused construct, keyed by rule id, enclosing method and the flagged line
with its whitespace collapsed -- never a line number, so an edit that moves a violation does not make it
new, and a deleted guard that creates one does. The engine runs the gate again on the baseline text and
blocks the keys the change holds more of; nothing here reads a baseline.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Callable, Iterable, Mapping

from chock_security.decision import FileText, Finding
from chock_security.flow import methods


def _scopes(text: FileText) -> Callable[[int], str]:
    """The name of the method a line sits in, or '' outside every method body the flow model found."""
    spans = sorted((m.body[0][0], m.body[-1][0], m.name) for m in methods(text))
    starts = [start for start, _, _ in spans]

    def scope(line_no: int) -> str:
        index = bisect_right(starts, line_no) - 1
        return spans[index][2] if index >= 0 and line_no <= spans[index][1] else ""

    return scope


def key(finding: Finding, scope: str) -> str:
    """rule id | enclosing method | flagged line, whitespace collapsed."""
    return f"{finding.rule_id}|{scope}|{' '.join(finding.line.split())}"


def document(findings: Iterable[Finding], files: Iterable[FileText]) -> dict[str, list[dict[str, object]]]:
    """The `{"findings": [...]}` the engine compares against the baseline run's."""
    texts: Mapping[str, FileText] = {f.path: f for f in files}
    scopes: dict[str, Callable[[int], str]] = {}
    rows = []
    for finding in findings:
        scope = scopes.setdefault(finding.path, _scopes(texts[finding.path]))
        rows.append(
            {
                "key": key(finding, scope(finding.line_no)),
                "path": finding.path,
                "line": finding.line_no,
                "message": finding.summary(),
            }
        )
    return {"findings": rows}

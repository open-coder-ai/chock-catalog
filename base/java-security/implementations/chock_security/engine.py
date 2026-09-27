"""Run the rules a front end can act on, at the verdict the selection gave each one."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import replace

from chock_security.decision import ALLOW, FileText, Finding
from chock_security.rules import registry

#: Per-occurrence waiver, named per rule so waiving one does not waive its neighbours.
PRAGMA = "chock: allow "

#: The text of a path as a human last committed it, or None when it has none (a new file).
Reviewed = Callable[[str], "str | None"]


def reviewed_lines(text: FileText, reviewed: str | None) -> set[int]:
    """The lines of `text` whose waiver a human put there.

    A waiver is a reviewer's decision, never the agent's. Each waived line counts only while the
    committed text holds the same line, as many times as it holds it: a waiver the agent wrote, or
    a copy of a committed one pasted somewhere new, is not among them.
    """
    left = Counter(line.strip() for line in (reviewed or "").splitlines() if PRAGMA in line)
    honoured: set[int] = set()
    for line_no, line in enumerate(text.lines, 1):
        key = line.strip()
        if PRAGMA in line and left[key] > 0:
            left[key] -= 1
            honoured.add(line_no)
    return honoured


def waiver_on(finding: Finding, text: FileText) -> bool:
    """Read on the file's own line: a rule may report the line with its comments blanked, and the
    waiver is a comment."""
    lines = text.lines
    line = lines[finding.line_no - 1] if 0 < finding.line_no <= len(lines) else finding.line
    return f"{PRAGMA}{finding.rule_id}" in line


def evaluate(files: Iterable[FileText], verdicts: Mapping[str, str], reviewed: Reviewed | None = None) -> list[Finding]:
    """Findings from every rule the selection did not set to allow, each carrying its verdict.

    `reviewed` is given where the agent wrote the text -- as it writes, and at its turn's end --
    and a waiver then counts only on a line a human committed. Without it every waiver counts: at
    commit and push the person committing is the one who reviews it.
    """
    acting = {rule_id: rule for rule_id, rule in registry().items() if verdicts.get(rule_id, ALLOW) != ALLOW}
    findings: list[Finding] = []
    for text in files:
        honoured = None
        if reviewed is not None:
            honoured = reviewed_lines(text, reviewed(text.path)) if PRAGMA in text.text else set()
        for rule_id, rule in acting.items():
            if not rule.reads(text):
                continue
            found = (replace(f, verdict=verdicts[rule_id], cwe=rule.cwe) for f in rule.scan(text))
            findings.extend(
                f for f in found if not (waiver_on(f, text) and (honoured is None or f.line_no in honoured))
            )
    return findings

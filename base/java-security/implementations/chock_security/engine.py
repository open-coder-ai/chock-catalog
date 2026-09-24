"""Run the rules a front end can act on, at the verdict the selection gave each one."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace

from chock_security.decision import ALLOW, FileText, Finding
from chock_security.rules import registry

#: Per-occurrence waiver, named per rule so waiving one does not waive its neighbours.
PRAGMA = "chock: allow "


def _waived(finding: Finding, text: FileText) -> bool:
    """Read on the file's own line: a rule may report the line with its comments blanked, and the
    waiver is a comment."""
    lines = text.lines
    line = lines[finding.line_no - 1] if 0 < finding.line_no <= len(lines) else finding.line
    return f"{PRAGMA}{finding.rule_id}" in line


def evaluate(files: Iterable[FileText], verdicts: Mapping[str, str]) -> list[Finding]:
    """Findings from every rule the selection did not set to allow, each carrying its verdict."""
    acting = {rule_id: rule for rule_id, rule in registry().items() if verdicts.get(rule_id, ALLOW) != ALLOW}
    findings: list[Finding] = []
    for text in files:
        for rule_id, rule in acting.items():
            if not rule.reads(text):
                continue
            found = (replace(f, verdict=verdicts[rule_id], cwe=rule.cwe) for f in rule.scan(text))
            findings.extend(f for f in found if not _waived(f, text))
    return findings

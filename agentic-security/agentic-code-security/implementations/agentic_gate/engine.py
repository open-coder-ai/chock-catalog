"""Run the rules the selection leaves on, and keep only what the change adds and no human waived."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping

from agentic_gate.changed import only_new
from agentic_gate.model import ALLOW, FileText, Finding, Rule
from agentic_gate.registry import registry

#: `# chock: allow <rule-id>[, <rule-id>]` or `// chock: allow <rule-id>`, on the line or the line above.
PRAGMA = "chock: allow "
_WAIVER = re.compile(r"chock:\s*allow\s+([a-z0-9-]+(?:\s*,\s*[a-z0-9-]+)*)")
_COMMENT_ONLY = re.compile(r"^\s*(#|//)")

#: The text of a path as last committed, or None when it has none (a new file).
Reader = Callable[[str], "str | None"]


def _waived_ids(line: str) -> set[str]:
    found = _WAIVER.search(line)
    return {part.strip() for part in found.group(1).split(",")} if found else set()


def reviewed_lines(text: FileText, reviewed: str | None) -> set[int]:
    """The lines of `text` whose waiver a human put there: the same line in the committed text.

    Each waived line counts only while the committed text holds it, as many times as it holds it,
    so a waiver the agent wrote, or a committed one pasted somewhere new, is not among them.
    """
    left = Counter(line.strip() for line in (reviewed or "").splitlines() if PRAGMA in line)
    honoured: set[int] = set()
    for line_no, line in enumerate(text.lines, 1):
        key = line.strip()
        if PRAGMA in line and left[key] > 0:
            left[key] -= 1
            honoured.add(line_no)
    return honoured


def _waiver_lines(finding: Finding, lines: list[str]) -> Iterable[int]:
    """The line a waiver for this finding may sit on: its own, or a comment-only line above."""
    yield finding.line_no
    above = finding.line_no - 1
    if above >= 1 and _COMMENT_ONLY.match(lines[above - 1]):
        yield above


def waived(finding: Finding, text: FileText, honoured: set[int] | None) -> bool:
    """Whether a waiver naming this rule sits where it may. JSON has no comments: no waiver there."""
    if text.kind == "json":
        return False
    lines = text.lines
    for line_no in _waiver_lines(finding, lines):
        if finding.rule_id in _waived_ids(lines[line_no - 1]) and (honoured is None or line_no in honoured):
            return True
    return False


def _scan(text: FileText, acting: Mapping[str, Rule]) -> list[Finding]:
    lines = text.lines
    findings: list[Finding] = []
    for rule in acting.values():
        if not rule.reads(text):
            continue
        for hit in rule.scan(text):
            line = lines[hit.line_no - 1].strip() if 0 < hit.line_no <= len(lines) else ""
            message = f"{hit.detail} Fix: {rule.fix}"
            findings.append(
                Finding(rule.id, text.path, hit.line_no, line, message, rule.cwe, rule.asi, hit.related, hit.by_diff)
            )
    return findings


def evaluate(
    writes: Mapping[str, str],
    verdicts: Mapping[str, str],
    head: Reader,
    *,
    human: bool,
    before: Callable[[str, str], str | None] | None = None,
) -> list[Finding]:
    """Findings from every rule the selection did not set to allow, on what the change adds.

    A finding stays when a line it involves is new against the baseline `before(path, written)` names
    (HEAD when not given): see `changed`. `human` is the commit, the push and CI, where any waiver
    counts; everywhere else (as the agent writes, and at its turn's end) a waiver counts only on a line
    a human already committed.
    """
    acting = {rule_id: rule for rule_id, rule in registry().items() if verdicts.get(rule_id, ALLOW) != ALLOW}
    findings: list[Finding] = []
    for path, body in writes.items():
        committed = head(path)
        others = tuple(other for other_path, other in writes.items() if other_path != path)
        text = FileText(path, body, committed, others)
        found = _scan(text, acting)
        found = only_new(found, text, before(path, body) if before else committed)
        honoured = None if human else reviewed_lines(text, committed)
        findings.extend(f for f in found if not waived(f, text, honoured))
    return findings

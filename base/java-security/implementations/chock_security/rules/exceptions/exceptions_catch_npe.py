"""Catching NullPointerException to detect a null instead of checking for it turns a programming
error into expected control flow, and hides the real null wherever it actually came from."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.exceptions._catch import catch_clauses

RULE_ID = "exceptions-catch-npe"

_FACTS = facts("exceptions")["catch_npe"]

_MESSAGE = (
    "Catching NullPointerException to detect a null turns a programming error into expected "
    "control flow, and the exception can come from any dereference in this block, not just the "
    "one you meant to guard -- so it hides the real null wherever it actually came from. Check "
    f"for null explicitly instead. 'chock: allow {RULE_ID}' on this line if this genuinely wraps "
    "third-party code you cannot null-check."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every catch clause naming NullPointerException directly."""
    for clause in catch_clauses(text):
        if any(t in _FACTS["types"] for t in clause.types):
            line = text.lines[clause.line_no - 1] if 0 < clause.line_no <= len(text.lines) else ""
            yield Finding(RULE_ID, text.path, clause.line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="exceptions",
    title="NullPointerException caught",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(catch): NullPointerException -- check for null explicitly instead of catching it",
    refuses="`catch (NullPointerException e)`, alone or in a multi-catch",
    silent_on="`catch (Exception e)`; `catch (IllegalArgumentException e)`; an explicit `if (x == null)` check",
    cwe=("CWE-395",),
    references=("https://rules.sonarsource.com/java/RSPEC-1696/",),
)

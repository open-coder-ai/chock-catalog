"""Catching Throwable or Error catches things a program has no business intercepting --
OutOfMemoryError, StackOverflowError, an assertion failure -- and usually means the process should
have died instead of limping on in a state nobody designed for."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.exceptions._catch import catch_clauses

RULE_ID = "exceptions-catch-broad"

_FACTS = facts("exceptions")["catch_broad"]

_MESSAGE = (
    "This catches {caught}, which also catches OutOfMemoryError, StackOverflowError and every "
    "other JVM error a program has no business intercepting -- these usually mean the process "
    "should stop, not limp on in a state nobody designed for. Catch the specific exception types "
    f"this code can actually recover from instead. 'chock: allow {RULE_ID}' on this line if this "
    "really is a top-level boundary that must never propagate."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every catch clause naming Throwable or Error directly (not a specific Error subclass)."""
    for clause in catch_clauses(text):
        caught = next((t for t in clause.types if t in _FACTS["types"]), None)
        if caught is not None:
            line = text.lines[clause.line_no - 1] if 0 < clause.line_no <= len(text.lines) else ""
            yield Finding(RULE_ID, text.path, clause.line_no, line, _MESSAGE.format(caught=caught))


RULE = Rule(
    id=RULE_ID,
    pack="exceptions",
    title="Throwable or Error caught",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(catch): Throwable|Error directly -- catch the specific exception types this code can recover from",
    refuses="`catch (Throwable ...)` or `catch (Error ...)`, alone or in a multi-catch",
    silent_on="`catch (Exception e)`; `catch (RuntimeException e)`; a specific Error subclass such as `catch (OutOfMemoryError e)` or `catch (AssertionError e)`",
    cwe=("CWE-396",),
    references=("https://rules.sonarsource.com/java/RSPEC-1181/",),
)

"""A catch block with nothing in it swallows the exception outright -- whatever failed keeps
failing silently, and the next person to touch this code has no idea it can happen at all."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.exceptions._catch import catch_clauses

RULE_ID = "exceptions-empty-catch"

#: A caught variable named for being dropped states the intent a comment would; IntelliJ's
#: empty-catch inspection honours the same names.
_INTENDED = frozenset(facts("exceptions")["intended_empty_catch_names"])

_MESSAGE = (
    "This catch block for {types} has no statements, so the exception is silently discarded -- "
    "whatever failed keeps failing with no trace of it. Handle it, log it with context, or "
    f"rethrow it; a genuinely-ignorable exception still needs a comment explaining why. 'chock: "
    f"allow {RULE_ID}' on this line if silence really is correct here."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every catch block whose body has no statements and no comment explaining the silence."""
    for clause in catch_clauses(text):
        if clause.code_body.strip() or clause.raw_body.strip():
            continue  # has a statement, or at least a comment justifying the silence
        if clause.variable in _INTENDED:
            continue  # `catch (X ignored)` says it on purpose, as a comment would
        line = text.lines[clause.line_no - 1] if 0 < clause.line_no <= len(text.lines) else ""
        yield Finding(RULE_ID, text.path, clause.line_no, line, _MESSAGE.format(types=" | ".join(clause.types)))


RULE = Rule(
    id=RULE_ID,
    pack="exceptions",
    title="Empty catch block",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(catch): an exception with an empty block and no comment -- handle it, log it with context, or rethrow it",
    refuses="a catch block with no statements and no comment inside it",
    silent_on="a catch block containing a comment explaining why nothing is done, or whose variable is named ignored/ignore/expected; any catch block with at least one statement",
    cwe=("CWE-1071",),
    references=(
        "https://rules.sonarsource.com/java/RSPEC-108/",
        "https://pmd.github.io/pmd/pmd_rules_java_errorprone.html#emptycatchblock",
    ),
)

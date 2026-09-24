"""`x = x;` changes nothing -- it is either dead code left over from a refactor, or (more often)
a typo for `this.x = x;`, a parameter meant to reach the field it shadows but never does."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-self-assignment"

_SELF_ASSIGN = re.compile(r"^(\w+)\s*=\s*\1\s*;$")

_MESSAGE = (
    "{var} = {var}; assigns the variable to itself and changes nothing. If this was meant to "
    "set a field from a same-named parameter, write this.{var} = {var}; instead -- as written, "
    f"the field keeps its old value. 'chock: allow {RULE_ID}' on this line if the self-"
    "assignment is deliberate (rare)."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every bare `x = x;` statement."""
    for line_no, line in enumerate(code(text), 1):
        match = _SELF_ASSIGN.match(line.strip())
        if not match:
            continue
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(var=match.group(1)))


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="Variable assigned to itself",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(statement): x = x; -- changes nothing; likely meant this.x = x; to set the field from a same-named parameter",
    refuses="x = x; as a bare statement, both sides the exact same plain variable name",
    silent_on="this.x = x; (legitimate field-from-parameter assignment); x = y; count = count + 1;",
    cwe=("CWE-1164",),
    references=(
        "https://rules.sonarsource.com/java/RSPEC-1656/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#sa-self-assignment-of-field-sa-field-self-assignment",
    ),
)

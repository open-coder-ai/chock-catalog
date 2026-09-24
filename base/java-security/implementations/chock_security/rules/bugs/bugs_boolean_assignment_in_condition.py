"""`if (found = true)` assigns rather than compares: the condition is now always true (or always
false for `= false`), and whatever `found` held before is silently overwritten every time."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-boolean-assignment-in-condition"

#: The whole condition is exactly `name = true` or `name = false` -- a mixed condition like
#: `if (found = true && x > 0)` is a different, less certain shape this rule leaves alone.
_BOOLEAN_ASSIGN = re.compile(r"\b(if|while)\s*\(\s*(\w+)\s*=\s*(true|false)\s*\)")

_MESSAGE = (
    "if/while ({var} = {value}) assigns {value} to {var} inside the condition instead of "
    "comparing -- the condition is always {value}, and {var}'s previous value is silently "
    f"overwritten every time this runs. Use == to compare, or move the assignment above the "
    f"condition if it was meant to happen. 'chock: allow {RULE_ID}' on this line if the "
    "assignment-as-condition is deliberate."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `if`/`while` whose entire condition assigns a boolean literal."""
    for line_no, line in enumerate(code(text), 1):
        match = _BOOLEAN_ASSIGN.search(line)
        if not match:
            continue
        message = _MESSAGE.format(var=match.group(2), value=match.group(3))
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], message)


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="Boolean literal assigned inside an if/while condition",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(condition): if (flag = true) | while (flag = false) -- use == to compare, not = to assign",
    refuses="if (x = true), while (x = false) -- assigning a boolean literal as the whole condition",
    silent_on="if (x == true); while (x); if (x = computeFlag()); if (a && b)",
    cwe=("CWE-481",),
    references=(
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#qba-method-assigns-boolean-literal-in-boolean-expression-qba-questionable-boolean-assignment",
    ),
)

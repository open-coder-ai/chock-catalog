"""NaN compares unequal to every value, including itself, by IEEE 754 definition -- `x ==
Double.NaN` is not a typo-shaped bug so much as an expression that always evaluates to false."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-nan-comparison"

_NAN = r"(?:Double|Float)\.NaN"
_COMPARISON = re.compile(rf"(?:{_NAN}\s*[=!]=|[=!]=\s*{_NAN})")

_MESSAGE = (
    "By IEEE 754 definition, NaN compares unequal to every value including itself, so this "
    "{op} always evaluates to {result} -- it can never do what the code around it expects. Use "
    "Double.isNaN(x) (or Float.isNaN(x) for float precision) to test for NaN instead."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `== Double.NaN` / `!= Float.NaN` comparison, in either operand order."""
    for line_no, line in enumerate(code(text), 1):
        match = _COMPARISON.search(line)
        if not match:
            continue
        op = "!=" if "!=" in match.group(0) else "=="
        result = "true" if op == "!=" else "false"
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(op=op, result=result))


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="Doomed test for equality to NaN",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(compare): x == Double.NaN | x != Float.NaN -- always false/true; use Double.isNaN(x)/Float.isNaN(x)"
    ),
    refuses="== or != against Double.NaN or Float.NaN, in either operand order",
    silent_on="Double.isNaN(x); Float.isNaN(x); Double.compare(x, Double.NaN)",
    cwe=("CWE-570",),
    references=(
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#fe-doomed-test-for-equality-to-nan-fe-test-if-equal-to-not-a-number",
    ),
)

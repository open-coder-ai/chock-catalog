"""`==`/`!=` compares String references, not contents -- two equal strings from different places
(one interned literal, one built at runtime) fail this check even though `.equals()` would pass."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-string-identity-comparison"

#: A string literal (its contents are blanked by code(), the quotes are not) or `new String(...)`
#: sitting on either side of `==`/`!=`.
_LITERAL = r'(?:"[^"]*"|new\s+String\s*\([^()]*\))'
_COMPARISON = re.compile(rf"(?:{_LITERAL}\s*[=!]=|[=!]=\s*{_LITERAL})")

_MESSAGE = (
    "This compares String references with {op}, not contents -- two equal strings built at "
    "different points in the program can compare unequal here even though .equals() would say "
    f"they match. Use .equals()/.equalsIgnoreCase() (or Objects.equals() if either side can be "
    f"null) instead. 'chock: allow {RULE_ID}' on this line if this is deliberately an identity "
    "check (e.g. testing for a specific interned sentinel)."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `==`/`!=` with a string literal or `new String(...)` on one side."""
    for line_no, line in enumerate(code(text), 1):
        match = _COMPARISON.search(line)
        if not match:
            continue
        op = "!=" if "!=" in match.group(0) else "=="
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(op=op))


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="String compared by reference with == or !=",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        'never(compare): stringVar == "literal" | stringVar != "literal" | == new String(...) '
        "-- use .equals()/.equalsIgnoreCase(), or Objects.equals() when either side can be null"
    ),
    refuses="a String variable compared with == or != against a string literal or new String(...)",
    silent_on=".equals()/.equalsIgnoreCase() calls; == against null; == between two plain variables",
    cwe=("CWE-597",),
    references=(
        "https://rules.sonarsource.com/java/RSPEC-4973/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#es-comparison-of-string-objects-using-or-es-comparing-strings-with-eq",
    ),
)

"""`int a, b;` hides that two variables were just introduced in one place a reader scans past --
one declaration per statement is easier to add to, delete from and diff."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "style-multiple-variable-declarations"

_TYPES = "|".join(facts("style")["multiple_variable_declarations"]["types"])
_MULTI_DECL = re.compile(
    rf"^\s*(?:(?:public|private|protected|static|final)\s+)*(?:{_TYPES})\s+"
    r"[A-Za-z_$]\w*\s*(?:=[^,;()]+)?\s*,\s*[A-Za-z_$]\w*"
)
_FOR_HEADER = re.compile(r"^\s*for\s*\(")

_MESSAGE = "This declares more than one variable in a single statement. Give each its own line."


def scan(text: FileText) -> Iterator[Finding]:
    """A `for (...)` header's own comma-separated init list is a different, accepted construct."""
    for line_no, line in enumerate(code(text), 1):
        if _FOR_HEADER.match(line):
            continue
        if _MULTI_DECL.match(line) and line.rstrip().endswith(";"):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="style",
    title="Multiple variables declared in one statement",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(declare): int a, b; -- one variable declaration per statement",
    refuses="`int a, b;`, `String first, last;`, `double x = 0, y = 0;`",
    silent_on="`int a; int b;` on separate lines; `for (int i = 0, j = len; i < j; i++, j--)`; `String name(int a, int b)` (a parameter list); "
    '`String url = builder.queryParam("city", city).build();` (a comma inside a method call, not a second declaration)',
    references=(
        "https://checkstyle.org/checks/coding/multiplevariabledeclarations.html",
        "https://rules.sonarsource.com/java/RSPEC-1659/",
    ),
)

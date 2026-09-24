"""A `static final` primitive or String that is not UPPER_SNAKE_CASE looks like a mutable field,
so a reader has no way to tell at the call site that it can never be reassigned."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "style-constant-name"

_FACTS = facts("style")["constant"]
_TYPES = "|".join(_FACTS["types"])
_CONSTANT = re.compile(
    r"\b(?:public|private|protected)?\s*(?:static\s+final|final\s+static)\s+"
    rf"(?:{_TYPES})\s+([A-Za-z_$][\w$]*)\s*="
)
_UPPER_SNAKE = re.compile(r"^[A-Z][A-Z0-9_]*$")

_MESSAGE = (
    "{name} is a static final constant but is not UPPER_SNAKE_CASE, so it reads like a field that "
    "can change. Rename it to shout that it cannot."
)


def scan(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(code(text), 1):
        for match in _CONSTANT.finditer(line):
            name = match.group(1)
            if name in _FACTS["exempt_names"] or _UPPER_SNAKE.match(name):
                continue
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(name=name))


RULE = Rule(
    id=RULE_ID,
    pack="style",
    title="Constant name not UPPER_SNAKE_CASE",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(name): static final int/long/short/byte/char/boolean/float/double/String not matching ^[A-Z][A-Z0-9_]*$",
    refuses="`private static final String tableName = ...;`, `static final int maxRetries = 3;`",
    silent_on="`private static final String TABLE_NAME = ...;`; `private static final long serialVersionUID = 1L;`; "
    "`private static final Logger log = ...;` (not a primitive or String)",
    references=(
        "https://checkstyle.org/checks/naming/constantname.html",
        "https://rules.sonarsource.com/java/RSPEC-115/",
    ),
)

"""String, LocalDate and friends are immutable: `.trim()`, `.plusDays(1)` and their kin never
change the receiver, they return a new value -- call one as a bare statement and the result, the
only place the work went, is thrown away and nothing happens."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "bugs-ignored-return-value"

_METHODS = facts("bugs")["ignored_return"]["methods"]

#: A bare statement: the whole line is `receiver.method(args);`, nothing assigns or returns it.
_IGNORED_CALL = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.(" + "|".join(_METHODS) + r")\([^;]*\)\s*;$")

_MESSAGE = (
    "The result of .{method}(...) is never used. This receiver's type is immutable -- {method} "
    "returns a new value rather than changing the receiver in place -- so calling it as a bare "
    "statement does nothing observable. Assign the result back (or return it) if this call was "
    f"meant to take effect. 'chock: allow {RULE_ID}' on this line if it is called only for a "
    "side effect this rule cannot see (rare for an immutable type)."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every bare-statement call to a known immutable-type method whose result is thrown away."""
    for line_no, line in enumerate(code(text), 1):
        match = _IGNORED_CALL.match(line.strip())
        if not match:
            continue
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(method=match.group(1)))


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="Return value of an immutable-type method ignored",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(statement): s.trim(); | date.plusDays(1); (or strip/toUpperCase/toLowerCase/"
        "substring/concat/with*/plus*/minus* as a bare statement) -- assign the result back"
    ),
    refuses="s.trim(); str.toUpperCase(); date.plusDays(1); as a standalone statement, result unused",
    silent_on="x = s.trim(); return s.trim(); if (s.trim().isEmpty()) ...; list.add(x); (List.add has real side effects)",
    cwe=("CWE-252",),
    references=(
        "https://rules.sonarsource.com/java/RSPEC-2201/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#rv-method-ignores-return-value-rv-return-value-ignored",
    ),
)

"""An array's toString() is Object's -- it prints the type and an identity hash, e.g. [C@16f0472,
never the array's contents. Arrays.toString(array) is the call that was probably meant."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-array-tostring"

_ARRAY_DECL = re.compile(r"\b[\w.]+(?:<[^<>]*>)?\[\]\s+(\w+)\b")
_TOSTRING_CALL = re.compile(r"\b(\w+)\.toString\(\s*\)")

_MESSAGE = (
    "{name} is an array, and calling .toString() on it prints the type and an identity hash "
    "(something like [Ljava.lang.String;@1b6d3586), never the array's contents. Use "
    "Arrays.toString({name}) (or Arrays.deepToString for a nested array) instead."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `arrayVar.toString()` where `arrayVar` was declared as an array in this file."""
    lines = code(text)
    array_names = {m.group(1) for line in lines for m in _ARRAY_DECL.finditer(line)}
    if not array_names:
        return
    for line_no, line in enumerate(lines, 1):
        for match in _TOSTRING_CALL.finditer(line):
            if match.group(1) not in array_names:
                continue
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(name=match.group(1)))


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="toString() invoked on an array",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): arrayVar.toString() -- prints the type and identity hash, not the contents; use Arrays.toString(arrayVar)",
    refuses="<arrayVariable>.toString() where that variable was declared as an array type",
    silent_on="Arrays.toString(array); Arrays.deepToString(array); list.toString() on a List/Collection",
    references=(
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#useless-string-invocation-of-tostring-on-an-array-dmi-invoking-tostring-on-array",
    ),
)

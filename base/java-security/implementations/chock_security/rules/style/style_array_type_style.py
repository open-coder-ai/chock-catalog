"""`String args[]` puts the array-ness on the variable, so every other declaration on the line
looks non-array even when it shares the same type -- Java's own style puts it on the type."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "style-array-type-style"

_NOT_A_TYPE = "|".join(facts("style")["modifiers"])
_C_STYLE = re.compile(rf"\b(?!(?:{_NOT_A_TYPE})\b)[A-Za-z_$][\w$]*\s+([A-Za-z_$][\w$]*)(?:\s*\[\])+")

_MESSAGE = "{name}[] puts the array brackets on the variable name (C style). Java style puts them on the type instead: Type[] {name}."


def scan(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(code(text), 1):
        match = _C_STYLE.search(line)
        if match:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(name=match.group(1)))


RULE = Rule(
    id=RULE_ID,
    pack="style",
    title="C-style array declaration",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(declare): Type name[] -- write Type[] name instead",
    refuses="`String args[]`, `public static void main(String argv[])`, `int matrix[][]`",
    silent_on="`String[] args`; `int[] matrix`; `new int[]{1, 2, 3}`; `values[i]` (an array access, not a declaration)",
    references=(
        "https://checkstyle.org/checks/misc/arraytypestyle.html",
        "https://rules.sonarsource.com/java/RSPEC-1197/",
    ),
)

"""A lowercase `l` suffix on a long literal is a digit `1` in most monospace fonts -- `10l` and
`101` are one keystroke apart and read identically at a glance."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "style-upper-ell"

_LOWER_ELL = re.compile(r"(?<![\w.])(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*)l\b")

_MESSAGE = "This long literal's lowercase `l` suffix looks like the digit 1. Use an upper-case `L` instead."


def scan(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(code(text), 1):
        if _LOWER_ELL.search(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="style",
    title="Long literal with lowercase l suffix",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(write): a long literal suffixed with lowercase l -- use uppercase L",
    refuses="`10l`, `0x1Fl`, `0b101l`",
    silent_on="`10L`, `0x1FL`; `10` (no suffix, an int); a variable named `l`; the letter `l` inside a string or comment",
    references=("https://checkstyle.org/checks/misc/upperell.html", "https://rules.sonarsource.com/java/RSPEC-818/"),
)

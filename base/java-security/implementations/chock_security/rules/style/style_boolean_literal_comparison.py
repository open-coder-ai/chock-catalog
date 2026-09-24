"""`x == true` and `x != false` say nothing `x` and `!x` do not already say, and read worse."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "style-boolean-literal-comparison"

_COMPARISON = re.compile(r"(?:==|!=)\s*(?:true|false)\b|\b(?:true|false)\s*(?:==|!=)")

_MESSAGE = (
    "Comparing to a boolean literal is redundant: `x == true` is just `x`, and `x == false` is "
    "`!x`. Drop the comparison instead of spelling it out."
)


def scan(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(code(text), 1):
        if _COMPARISON.search(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="style",
    title="Boolean literal compared with == / !=",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(compare): expr == true|false|expr != true|false -- use the expression itself, negated with ! if needed",
    refuses="`x == true`, `x == false`, `x != true`, `x != false`, in either operand order",
    silent_on="`x`, `!x`; `Boolean.TRUE.equals(x)`; `x == y` comparing two variables; the words `true`/`false` inside a string or comment",
    references=("https://rules.sonarsource.com/java/RSPEC-1125/",),
)

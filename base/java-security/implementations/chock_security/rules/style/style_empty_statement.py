"""`if (cond);` compiles, runs the semicolon and silently does nothing to the block that follows
it -- the bug is invisible unless you count parentheses."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "style-empty-statement"

_FACTS = facts("style")
_KEYWORD = re.compile(r"\b(?:" + "|".join(_FACTS["control_keywords"]) + r")\s*\(")

_MESSAGE = (
    "This closing parenthesis is immediately followed by an empty statement (`;`), so the block "
    "that looks like it belongs to this condition never runs conditionally -- it always runs. Add "
    "braces around the intended body, or remove the stray `;`."
)


def _matching_close(line: str, open_index: int) -> int | None:
    """The index of the `)` that closes the `(` at `open_index`, on this same line, or None."""
    depth = 0
    for index in range(open_index, len(line)):
        depth += (line[index] == "(") - (line[index] == ")")
        if depth == 0:
            return index
    return None


def scan(text: FileText) -> Iterator[Finding]:
    """Every `if(...)`, `for(...)` or `while(...)` whose condition is immediately followed, on the
    same line, by a bare `;` -- the single-line shape a regex can decide without a parser."""
    for line_no, line in enumerate(code(text), 1):
        for match in _KEYWORD.finditer(line):
            close = _matching_close(line, match.end() - 1)
            if close is not None and line[close + 1 :].lstrip().startswith(";"):
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="style",
    title="Empty statement after if/for/while",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(write): if (...); / for (...); / while (...); -- an empty statement where a block was meant",
    refuses="`if (cond);`, `for (...);`, `while (cond);` on one line, with nothing or only whitespace between `)` and `;`",
    silent_on="`if (cond) {}`; `if (cond) doThing();`; `while (queue.poll() != null) {}`; a `;` inside a string or comment",
    cwe=("CWE-1071",),
    references=(
        "https://checkstyle.org/checks/coding/emptystatement.html",
        "https://rules.sonarsource.com/java/RSPEC-1116/",
    ),
)

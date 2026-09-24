"""A return or throw directly inside a finally block silently swallows whatever exception was
propagating -- the finally's outcome replaces it -- which is almost never what the author meant
and is the single most confusing thing a finally block can do."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.rules.exceptions._catch import finally_blocks

RULE_ID = "exceptions-finally-control-flow"

_JUMP = re.compile(r"[{}]|\b(return|throw)\b")

_MESSAGE = (
    "This `{keyword}` sits directly inside a finally block, so it replaces whatever exception was "
    "already propagating out of the try -- the original failure is silently discarded. Move this "
    f"out of the finally block, or into an `if` guarding only the cleanup path. 'chock: allow "
    f"{RULE_ID}' on this line if replacing the exception is genuinely intended."
)


def _top_level_jumps(body: str) -> Iterator[tuple[int, str]]:
    """`return`/`throw` at the finally block's own nesting level -- not inside a nested block,
    where a loop's own `break`/`continue` or an inner try/catch's own throw does not escape it."""
    depth = 0
    for match in _JUMP.finditer(body):
        symbol = match.group(0)
        if symbol == "{":
            depth += 1
        elif symbol == "}":
            depth -= 1
        elif depth == 0:
            yield match.start(), symbol


def scan(text: FileText) -> Iterator[Finding]:
    """Every finally block with a `return` or `throw` at its own top level."""
    for line_no, body in finally_blocks(text):
        for offset, keyword in _top_level_jumps(body):
            jump_line = line_no + body.count("\n", 0, offset)
            line = text.lines[jump_line - 1] if 0 < jump_line <= len(text.lines) else ""
            yield Finding(RULE_ID, text.path, jump_line, line, _MESSAGE.format(keyword=keyword))


RULE = Rule(
    id=RULE_ID,
    pack="exceptions",
    title="return or throw inside a finally block",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(place): return|throw directly inside a finally block -- it silently replaces the exception the try was propagating",
    refuses="a `return` or `throw` statement at the finally block's own top level",
    silent_on="a `return`/`throw` inside a braced nested block (`if { }`, a loop, or an inner try/catch) within the finally block; `break`/`continue` anywhere in the finally block",
    cwe=("CWE-584",),
    references=("https://rules.sonarsource.com/java/RSPEC-1143/",),
)

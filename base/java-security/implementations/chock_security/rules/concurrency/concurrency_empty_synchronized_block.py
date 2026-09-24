"""An empty synchronized block still pays for acquiring and releasing the lock, and still forces
a happens-before edge -- but with nothing inside it, that ordering guarantee protects no read or
write. It is either leftover code, or a memory-barrier trick that deserves a comment, not silence."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "concurrency-empty-synchronized-block"

_SYNC_OPEN = re.compile(r"synchronized\s*\([^()]*\)\s*\{")
_WINDOW = 40

_MESSAGE = (
    "This synchronized block is empty. It still pays the cost of acquiring and releasing the "
    "lock and forces a happens-before edge, but with nothing inside, that ordering guarantee "
    "protects no read or write -- either the body was left out by mistake, or this is a memory-"
    "barrier trick that needs a comment explaining what it publishes."
)


def _is_empty(lines: list[str], start: int) -> bool:
    window = "\n".join(lines[start : start + _WINDOW])
    open_pos = window.index("{")
    depth = 0
    for index in range(open_pos, len(window)):
        depth += (window[index] == "{") - (window[index] == "}")
        if depth == 0:
            return window[open_pos + 1 : index].strip() == ""
    return False


def scan(text: FileText) -> Iterator[Finding]:
    """Every `synchronized (...) { }` block with nothing but whitespace/comments inside."""
    lines = code(text)
    for line_no, line in enumerate(lines, 1):
        if not _SYNC_OPEN.search(line):
            continue
        if _is_empty(lines, line_no - 1):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="concurrency",
    title="Empty synchronized block",
    suffixes=(".java",),
    scan=scan,
    constraint="never(block): synchronized (lock) { } -- pays for the lock and forces a happens-before edge that protects nothing; fill it in or remove it",
    refuses="synchronized (lock) { } with nothing but whitespace or a comment inside",
    silent_on="synchronized (lock) { doWork(); }; a synchronized method with a real body",
    cwe=("CWE-585",),
    references=("https://pmd.github.io/pmd/pmd_rules_java_codestyle.html#emptycontrolstatement",),
)

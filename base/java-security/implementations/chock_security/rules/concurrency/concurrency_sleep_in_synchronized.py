"""Thread.sleep() while holding a monitor keeps every other thread that needs that lock blocked
for the whole sleep, for no reason related to the work the lock protects -- it turns a lock hold
time of microseconds into the sleep duration."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.rules.concurrency._scope import enclosing_kinds
from chock_security.source import code

RULE_ID = "concurrency-sleep-in-synchronized"

_SLEEP_CALL = re.compile(r"\bThread\.sleep\s*\(")

_MESSAGE = (
    "Thread.sleep() is called here while a synchronized block's lock is held. Every other "
    "thread that needs this lock is blocked for the whole sleep, for no reason related to the "
    "work the lock protects. Move the sleep outside the synchronized block, or replace it with a "
    "timed wait() on the lock if it is actually waiting for a condition."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `Thread.sleep(...)` reached from inside a `synchronized` block."""
    lines = code(text)
    for line_no, line in enumerate(lines, 1):
        if not _SLEEP_CALL.search(line):
            continue
        if "synchronized" in enclosing_kinds(lines, line_no):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="concurrency",
    title="Thread.sleep() called while holding a lock",
    suffixes=(".java",),
    scan=scan,
    constraint="never(call): Thread.sleep(...) inside a synchronized block -- blocks every other thread waiting on that lock for the whole sleep; move it outside",
    refuses="Thread.sleep(...) reached from inside a synchronized(...) { } block",
    silent_on="Thread.sleep(...) outside any synchronized block; Thread.sleep(...) inside a plain while loop",
    references=("https://rules.sonarsource.com/java/RSPEC-2276/",),
)

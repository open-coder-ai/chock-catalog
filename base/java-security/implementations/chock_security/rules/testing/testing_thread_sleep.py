"""A test that sleeps a fixed number of milliseconds to wait for something is either too slow when
the something is fast, or still flaky when it is slower than the guess."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.testing._util import is_test_path
from chock_security.source import code

RULE_ID = "testing-thread-sleep"

_FACTS = facts("testing")
_SLEEP = re.compile(r"(?<![\w.])" + re.escape(_FACTS["sleep_call"]))

_MESSAGE = (
    "Thread.sleep in a test guesses how long an async operation takes, so it is either slower "
    "than it needs to be or still flaky on a loaded machine. Use Awaitility, a CountDownLatch, or "
    "the framework's own wait/verify-with-timeout instead."
)


def scan(text: FileText) -> Iterator[Finding]:
    if not is_test_path(text.path, _FACTS["test_path"]):
        return
    for line_no, line in enumerate(code(text), 1):
        if _SLEEP.search(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="testing",
    title="Thread.sleep in a test",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): Thread.sleep(...) in a test -- use Awaitility or an explicit wait instead",
    refuses="`Thread.sleep(500)` anywhere in a test class's body",
    silent_on="`Thread.sleep(...)` in production code (not a test file); `await().atMost(...)`; `Thread.sleep(` inside a comment or string",
    references=("https://rules.sonarsource.com/java/RSPEC-2925/",),
)

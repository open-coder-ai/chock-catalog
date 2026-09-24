"""wait() can return without anyone calling notify() -- a spurious wakeup is allowed by the JLS,
and another thread can grab the lock and change the condition between notify() and this thread
resuming. Only a loop that rechecks the condition after waking up handles both correctly."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.rules.concurrency._scope import enclosing_kinds
from chock_security.source import code

RULE_ID = "concurrency-wait-not-in-loop"

_WAIT_CALL = re.compile(r"\b(?:\w+\.)?wait\s*\(")
_LOOP_KINDS = {"while", "for"}

_MESSAGE = (
    "This wait() is not inside a while/for loop. wait() can return without anyone calling "
    "notify() (a spurious wakeup, allowed by the JLS), and another thread can change the "
    "condition between notify() and this thread actually resuming -- only a loop that rechecks "
    "the condition after waking up handles both. Wrap it: while (!condition) { x.wait(); }"
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `wait()` call not enclosed by a while or for loop."""
    lines = code(text)
    for line_no, line in enumerate(lines, 1):
        if not _WAIT_CALL.search(line):
            continue
        if _LOOP_KINDS.isdisjoint(enclosing_kinds(lines, line_no)):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="concurrency",
    title="wait() not called inside a loop",
    suffixes=(".java",),
    scan=scan,
    constraint="never(call): x.wait() outside a while/for loop -- spurious wakeups and races between notify() and resuming both need the condition rechecked",
    refuses="Object.wait()/x.wait() reached with no enclosing while or for loop",
    silent_on="while (!condition) { x.wait(); }; a wait() call inside a for loop",
    references=(
        "https://rules.sonarsource.com/java/RSPEC-2274/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#wa-wait-not-in-loop",
    ),
)

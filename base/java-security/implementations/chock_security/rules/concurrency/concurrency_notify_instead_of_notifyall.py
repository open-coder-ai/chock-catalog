"""notify() wakes an arbitrary one of the threads waiting on this monitor. If more than one is
waiting for different conditions, notify() can wake the wrong one -- it stays asleep, sometimes
forever, while the thread that was actually woken finds nothing to do. notifyAll() lets every
waiter recheck its own condition and go back to sleep if it still doesn't hold."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "concurrency-notify-instead-of-notifyall"

#: `notify()` with no receiver (implicit this) or explicit `this.notify()` -- the two forms that
#: unambiguously mean "this object's own monitor", as opposed to some other object's notify().
_BARE_NOTIFY = re.compile(r"(?<![.\w])notify\(\s*\)")
_THIS_NOTIFY = re.compile(r"\bthis\.notify\(\s*\)")

_MESSAGE = (
    "notify() wakes an arbitrary one of the threads waiting on this monitor. If more than one "
    "waiter is waiting for a different condition, notify() can wake the wrong one, which finds "
    "its condition still false and goes back to sleep -- while the thread that could actually "
    "proceed never wakes up. Use notifyAll() unless this monitor is provably used by exactly one "
    "waiter at a time."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every bare `notify()` or `this.notify()` call."""
    for line_no, line in enumerate(code(text), 1):
        if _BARE_NOTIFY.search(line) or _THIS_NOTIFY.search(line):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="concurrency",
    title="notify() used instead of notifyAll()",
    suffixes=(".java",),
    scan=scan,
    constraint="never(call): notify() | this.notify() -- wakes an arbitrary single waiter, which can be the wrong one; use notifyAll()",
    refuses="a bare notify() call, or this.notify()",
    silent_on="notifyAll(); lock.notify() (some other object's notify, judged separately from this object's own monitor)",
    references=("https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#no-notify-not-notifyall",),
)

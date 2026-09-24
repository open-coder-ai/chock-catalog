"""A string literal is interned and shared with every other identical literal in the JVM -- and a
`new Object()` built inline is a fresh, unshared instance every time. Locking on either means the
lock is not exclusive to this critical section (a literal) or protects nothing at all (a lock no
other thread can ever reach), and getClass() changes lock identity the moment a subclass appears."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "concurrency-synchronization-on-shared-lock"

_PATTERNS = {
    re.compile(r"synchronized\s*\(\s*\"[^\"]*\"\s*\)"): (
        "a string literal, which the JVM interns -- every other place in the process that "
        "happens to synchronize on an identical literal shares this exact lock, so this "
        "critical section is not exclusive to what it looks like it protects"
    ),
    re.compile(r"synchronized\s*\(\s*new\s+Object\s*\(\s*\)\s*\)"): (
        "a new Object() built right here -- a fresh, unshared instance every time this runs, "
        "so no other thread can ever contend for this exact lock and the synchronized block "
        "protects nothing"
    ),
    re.compile(r"synchronized\s*\(\s*getClass\s*\(\s*\)\s*\)"): (
        "getClass(), which returns the runtime class -- a subclass locks on a different Class "
        "object than its superclass's code expects, breaking the mutual exclusion between them"
    ),
    re.compile(r"synchronized\s*\(\s*(?:Boolean\.(?:TRUE|FALSE)|Integer\.valueOf\([^()]*\))\s*\)"): (
        "a cached boxed constant, shared with every other place in the process that happens to "
        "box the same value -- this critical section is not exclusive to what it looks like it "
        "protects"
    ),
}

_MESSAGE = (
    "This synchronizes on {reason}. Use a private final Object (or the enclosing instance/class "
    "you actually mean to lock) created once and never re-created, instead."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `synchronized (...)` locking on a string literal, `new Object()`, getClass() or a boxed constant."""
    for line_no, line in enumerate(code(text), 1):
        for pattern, reason in _PATTERNS.items():
            if pattern.search(line):
                yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(reason=reason))
                break


RULE = Rule(
    id=RULE_ID,
    pack="concurrency",
    title="synchronized on a string literal, new Object(), getClass() or a boxed constant",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        'never(lock): synchronized("literal"|new Object()|getClass()|Boolean.TRUE|Integer.valueOf(n)) '
        "-- none of these is a lock exclusive to this critical section; use a private final Object field"
    ),
    refuses='synchronized("a literal"); synchronized(new Object()); synchronized(getClass()); synchronized(Boolean.TRUE)',
    silent_on="synchronized(this); synchronized(lockField); synchronized(SomeClass.class)",
    references=(
        "https://rules.sonarsource.com/java/RSPEC-1860/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#dl-synchronization-on-shared-constant",
    ),
)

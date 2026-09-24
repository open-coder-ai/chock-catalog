"""Calling System.gc() asks the JVM to run a full collection right now -- on most collectors that
means a stop-the-world pause the application chose for itself, for a hint the JVM is free to
ignore anyway. Triggering GC is the collector's job, not application code's."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "resources-forced-gc"

_FACTS = facts("resources")["forced_gc"]

_MESSAGE = (
    "{call} explicitly triggers garbage collection, which on most collectors means an unplanned "
    "stop-the-world pause -- and the JVM is free to ignore the request anyway, so it buys nothing "
    "reliable. Let the collector decide when to run, or fix the allocation pattern that made this "
    f"feel necessary. 'chock: allow {RULE_ID}' on this line in benchmarking code that means to "
    "force it."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every explicit call that asks the JVM to collect or run pending finalizers right now."""
    for line_no, (raw, blanked) in enumerate(zip(text.lines, code(text), strict=True), 1):
        call = next((c for c in _FACTS["calls"] if c in blanked), None)
        if call is not None:
            yield Finding(RULE_ID, text.path, line_no, raw, _MESSAGE.format(call=call))


RULE = Rule(
    id=RULE_ID,
    pack="resources",
    title="Garbage collection triggered explicitly",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): System.gc()|Runtime.getRuntime().gc()|System.runFinalization() -- let the collector decide when to run",
    refuses="System.gc(), Runtime.getRuntime().gc(), or System.runFinalization() called from application code",
    silent_on="a comment or string mentioning garbage collection; gc() called on an unrelated object with a different receiver",
    references=("https://rules.sonarsource.com/java/RSPEC-1215/",),
)

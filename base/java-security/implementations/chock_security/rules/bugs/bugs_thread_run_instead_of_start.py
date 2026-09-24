"""Calling run() on a Thread executes it synchronously, on the calling thread, as an ordinary
method call -- start() is what schedules it to actually run concurrently on a new thread."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-thread-run-instead-of-start"

#: `new Thread(...).run()`, unambiguous regardless of the file around it.
_NEW_THREAD_RUN = re.compile(r"new\s+Thread\s*\([^;]*\)\s*\.\s*run\s*\(\s*\)")
#: A variable this file itself declared with the type `Thread`.
_THREAD_DECL = re.compile(r"\bThread\s+(\w+)\s*[=;]")
_RUN_CALL = re.compile(r"\b(\w+)\s*\.\s*run\s*\(\s*\)")

_MESSAGE = (
    "{expr}.run() calls run() as an ordinary method, synchronously, on the calling thread -- "
    "nothing here actually runs concurrently. Call {expr}.start() instead to schedule it on a "
    f"new thread. 'chock: allow {RULE_ID}' on this line if running it synchronously here is "
    "deliberate."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `.run()` called on `new Thread(...)` or on a variable this file declared as Thread."""
    lines = code(text)
    thread_names = {m.group(1) for line in lines for m in _THREAD_DECL.finditer(line)}
    for line_no, line in enumerate(lines, 1):
        if _NEW_THREAD_RUN.search(line):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(expr="new Thread(...)"))
            continue
        for match in _RUN_CALL.finditer(line):
            if match.group(1) in thread_names:
                yield Finding(
                    RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(expr=match.group(1))
                )


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="Thread.run() called instead of Thread.start()",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): thread.run() -- runs synchronously on the caller's thread; call thread.start() to actually run it concurrently",
    refuses="new Thread(...).run(); a variable declared `Thread x` later called as x.run()",
    silent_on="thread.start(); runnable.run() where runnable is not declared as a Thread; a class's own run() body",
    references=("https://rules.sonarsource.com/java/RSPEC-1217/",),
)

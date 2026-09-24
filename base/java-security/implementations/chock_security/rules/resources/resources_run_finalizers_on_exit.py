"""System.runFinalizersOnExit() runs every pending finalizer on JVM shutdown, on whatever thread
happens to trigger it, while other threads may still be using those objects -- Joshua Bloch calls
it one of the most dangerous methods in the Java libraries. It has been deprecated since Java 1.1
and removed outright in modern JDKs."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "resources-run-finalizers-on-exit"

_FACTS = facts("resources")["run_finalizers_on_exit"]

_MESSAGE = (
    "{call} runs every pending finalizer on shutdown while other threads may still hold and use "
    "those objects -- it was deprecated since Java 1.1 for exactly this reason and no longer "
    f"exists in current JDKs. Remove the call; there is no safe replacement. 'chock: allow "
    f"{RULE_ID}' on this line will not help on a JDK where the method has been removed entirely."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every call to the deprecated, since-removed runFinalizersOnExit."""
    for line_no, (raw, blanked) in enumerate(zip(text.lines, code(text), strict=True), 1):
        call = next((c for c in _FACTS["calls"] if c in blanked), None)
        if call is not None:
            yield Finding(RULE_ID, text.path, line_no, raw, _MESSAGE.format(call=call))


RULE = Rule(
    id=RULE_ID,
    pack="resources",
    title="runFinalizersOnExit called",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): System.runFinalizersOnExit(...)|Runtime.getRuntime().runFinalizersOnExit(...) -- there is no safe replacement, remove the call",
    refuses="System.runFinalizersOnExit(...) or Runtime.getRuntime().runFinalizersOnExit(...)",
    silent_on="a comment or string mentioning runFinalizersOnExit; System.runFinalization() (a different, merely explicit-GC-adjacent call)",
    references=(
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#dm-method-invokes-dangerous-method-runfinalizersonexit-dm-run-finalizers-on-exit",
    ),
)

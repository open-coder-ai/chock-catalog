"""Overriding Object.finalize() puts the object on the JVM's finalization queue, which delays
collection by at least one extra GC cycle and gives no guarantee it ever runs at all -- the method
has been deprecated for removal since Java 9 precisely because nothing sound can be built on it."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "resources-finalize-override"

_FACTS = facts("resources")["finalize"]

_FINALIZE = re.compile(r"\bvoid\s+finalize\s*\(\s*\)")

_MESSAGE = (
    "Overriding finalize() relies on the garbage collector to run cleanup, which it may delay "
    "indefinitely or never do at all -- Object.finalize() has been deprecated for removal since "
    "Java 9. Use try-with-resources, an explicit close()/shutdown() method, or "
    f"java.lang.ref.Cleaner instead. 'chock: allow {RULE_ID}' on this line if a legacy API forces "
    "it."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every declaration of a method named `finalize` taking no arguments."""
    for line_no, (raw, blanked) in enumerate(zip(text.lines, code(text), strict=True), 1):
        if _FINALIZE.search(blanked):
            yield Finding(RULE_ID, text.path, line_no, raw, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="resources",
    title="Object.finalize() overridden",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=f"never(override): {_FACTS['signature']}) -- use try-with-resources, close()/shutdown(), or java.lang.ref.Cleaner",
    refuses="a class declaring `void finalize()`, at any visibility",
    silent_on="a call to super.finalize() or this.finalize(); a method named finalize that takes arguments",
    references=("https://rules.sonarsource.com/java/RSPEC-1113/",),
)

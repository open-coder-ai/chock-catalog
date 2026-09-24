"""Constructing a boxed primitive or a String with `new` always allocates a fresh object, even for
a value the JVM already caches or an identical String already in the pool -- valueOf()/literals
give the same result for less memory and, since Java 9, `new Integer(...)` is deprecated for
removal entirely."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "performance-boxing-constructor"

_FACTS = facts("performance")["boxing_ctor"]

_NEW_BOXED = re.compile(r"\bnew\s+(" + "|".join(_FACTS["types"]) + r")\s*\(")

_MESSAGE = (
    "`new {type}(...)` always allocates a new object, even when {type}.valueOf(...) (or a "
    "literal) would return an existing, cached, or pooled instance -- and the boxed-type "
    "constructors are deprecated for removal since Java 9. Use {type}.valueOf(...) or a literal "
    f"instead. 'chock: allow {RULE_ID}' on this line if identity (a distinct object, not equal "
    "value) is genuinely required."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `new Integer/Long/.../Boolean/Character/String(...)`."""
    for line_no, line in enumerate(code(text), 1):
        match = _NEW_BOXED.search(line)
        if match:
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(type=match.group(1)))


RULE = Rule(
    id=RULE_ID,
    pack="performance",
    title="Boxed primitive or String constructed with new",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(construct): new Integer(...)|new Long(...)|new Short(...)|new Byte(...)|new Double(...)|new Float(...)|new Boolean(...)|new Character(...)|new String(...) -- use valueOf(...) or a literal",
    refuses="`new Integer/Long/Short/Byte/Double/Float/Boolean/Character/String(...)`",
    silent_on="Integer.valueOf(...), Long.valueOf(...), a literal; `new StringBuilder(...)` or `new StringBuffer(...)`",
    references=(
        "https://rules.sonarsource.com/java/RSPEC-2129/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#dm-number-ctor",
    ),
)

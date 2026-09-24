"""Vector, Hashtable and Stack synchronize every single-threaded call whether or not another
thread will ever touch them, paying lock overhead on every get/put/push for safety almost no
caller actually needs -- ArrayList, HashMap and ArrayDeque do the same job without it."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "performance-legacy-collection"

_FACTS = facts("performance")["legacy_collections"]

_NEW_LEGACY = re.compile(r"\bnew\s+(" + "|".join(_FACTS["types"]) + r")\s*[<(]")

_REPLACEMENT = {"Vector": "ArrayList", "Hashtable": "HashMap", "Stack": "ArrayDeque"}

_MESSAGE = (
    "{type} synchronizes every call whether or not another thread ever touches this instance, "
    "paying lock overhead on every access for safety almost no caller needs. Use "
    f"{{replacement}} instead, or java.util.concurrent's own type if this really is shared "
    f"across threads. 'chock: allow {RULE_ID}' on this line if an API you cannot change requires "
    "this exact type."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `new Vector/Hashtable/Stack(...)`."""
    for line_no, line in enumerate(code(text), 1):
        match = _NEW_LEGACY.search(line)
        if match:
            legacy = match.group(1)
            yield Finding(
                RULE_ID,
                text.path,
                line_no,
                text.lines[line_no - 1],
                _MESSAGE.format(type=legacy, replacement=_REPLACEMENT[legacy]),
            )


RULE = Rule(
    id=RULE_ID,
    pack="performance",
    title="Synchronized legacy collection (Vector/Hashtable/Stack) used",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(construct): new Vector(...)|new Hashtable(...)|new Stack(...) -- use ArrayList/HashMap/ArrayDeque, or java.util.concurrent for real thread-sharing",
    refuses="`new Vector(...)`, `new Hashtable(...)`, or `new Stack(...)`",
    silent_on="ArrayList, HashMap, ArrayDeque, LinkedList; java.util.concurrent types such as ConcurrentHashMap",
    references=("https://rules.sonarsource.com/java/RSPEC-1149/",),
)

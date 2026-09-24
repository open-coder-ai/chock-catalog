"""Throwing a bare Exception, RuntimeException, Throwable or Error gives every caller nothing to
catch selectively -- they either catch this exact generic type (and everything else that also
throws it) or catch nothing, so the type stops meaning anything."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "exceptions-generic-thrown"

_FACTS = facts("exceptions")["generic_throw"]

_THROW_NEW = re.compile(r"\bthrow\s+new\s+((?:java\.lang\.)?(?:Exception|RuntimeException|Throwable|Error))\s*\(")

_MESSAGE = (
    "This throws a bare {type}, so every caller either catches this exact generic type -- and "
    "everything else that also throws it -- or catches nothing at all. Define and throw a "
    f"specific exception type instead. 'chock: allow {RULE_ID}' on this line if no caller is "
    "meant to distinguish this failure from any other."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `throw new Exception/RuntimeException/Throwable/Error(...)`."""
    for line_no, line in enumerate(code(text), 1):
        match = _THROW_NEW.search(line)
        if match and match.group(1) in _FACTS["types"]:
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(type=match.group(1)))


RULE = Rule(
    id=RULE_ID,
    pack="exceptions",
    title="Generic exception thrown",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(throw): new Exception(...)|new RuntimeException(...)|new Throwable(...)|new Error(...) -- define and throw a specific exception type",
    refuses="`throw new Exception(...)`, `new RuntimeException(...)`, `new Throwable(...)`, or `new Error(...)`",
    silent_on="`throw new IllegalArgumentException(...)`, a custom exception subclass, `throws Exception` on a method signature, or `throw e;` rethrowing a caught exception",
    cwe=("CWE-397",),
    references=("https://rules.sonarsource.com/java/RSPEC-112/",),
)

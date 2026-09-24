"""Turning off session-fixation protection lets a session id set before login carry through it,
so an attacker who planted that id is now logged in as the victim too."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "spring-session-fixation-disabled"

_GUARD = facts("spring")["security_guard_tokens"]
_FACTS = facts("spring")["session_fixation"]
_LAMBDA = re.compile(_FACTS["lambda"])
_KOTLIN_OPEN = re.compile(_FACTS["kotlin_open"])

_MESSAGE = (
    "This turns off session-fixation protection, so a session id an attacker set before the "
    "victim logged in stays valid after login -- the attacker is now logged in as the victim too. "
    "Use the default (migrateSession()) or changeSessionId() so login always issues a fresh id; a "
    f"chain that manages its own session lifecycle needs 'chock: allow {RULE_ID}' on this line."
)


def _kotlin_block_none(text: FileText) -> Iterator[int]:
    lines = text.lines
    for line_no, line in enumerate(lines, 1):
        if not _KOTLIN_OPEN.search(line):
            continue
        window = "\n".join(lines[line_no - 1 : line_no + 5])
        depth = 0
        closed_at = None
        for offset, ch in enumerate(window):
            depth += (ch == "{") - (ch == "}")
            if depth <= 0 and ch == "}":
                closed_at = offset
                break
        body = window[:closed_at] if closed_at is not None else window
        if _FACTS["kotlin_token"] in body:
            yield line_no


def scan(text: FileText) -> Iterator[Finding]:
    """`.sessionFixation().none()` in any of its literal, lambda, or Kotlin DSL spellings."""
    if not text.holds(*_GUARD):
        return
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["literal"] in line or _LAMBDA.search(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)
    for line_no in _kotlin_block_none(text):
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Session-fixation protection disabled",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(disable): sessionFixation().none()|sessionFixation { none() } "
        "-- keep migrateSession() or changeSessionId() so login always issues a fresh session id"
    ),
    refuses="sessionFixation().none(), its lambda form, and the Kotlin DSL block",
    silent_on="sessionFixation().migrateSession()/changeSessionId(), and files with no HttpSecurity",
    cwe=("CWE-384",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",),
)

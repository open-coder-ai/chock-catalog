"""Disabling CSRF protection on a session-backed HttpSecurity chain, in any of its spellings."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "spring-csrf-disabled"

_GUARD = facts("spring")["security_guard_tokens"]
_FACTS = facts("spring")["csrf"]
_LAMBDA = re.compile(_FACTS["lambda_disable"])
_KOTLIN_OPEN = re.compile(_FACTS["kotlin_open"])

_MESSAGE = (
    "This turns off CSRF protection for every request the chain covers. That is correct for a "
    "stateless, token-authenticated API that never rides on a browser session or cookie -- but "
    "wrong for anything a browser session can still reach. If this chain is genuinely stateless, "
    "add 'chock: allow {rule}' on this line naming that (no session, no cookie auth); otherwise "
    "scope it with ignoringRequestMatchers(...) to the specific paths that need it, such as a "
    "webhook endpoint verified by its own signature."
).format(rule=RULE_ID)


def _kotlin_block_disables(text: FileText) -> Iterator[int]:
    """`csrf { disable() }`, open brace and the call on the same line or within a few after it."""
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
        if _FACTS["kotlin_disable_token"] in body:
            yield line_no


def scan(text: FileText) -> Iterator[Finding]:
    """A `.csrf()`/`csrf { }` disable, in a file this security chain configures at all."""
    if not text.holds(*_GUARD):
        return
    for line_no, line in enumerate(text.lines, 1):
        if any(form in line for form in _FACTS["literal_disable"]) or _LAMBDA.search(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)
    for line_no in _kotlin_block_disables(text):
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="CSRF protection disabled",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(disable): .csrf().disable()|csrf(...::disable)|csrf { disable() } "
        "-- fine only for a stateless token API; otherwise scope it with ignoringRequestMatchers"
    ),
    refuses="csrf().disable(), the method-reference and lambda forms, and the Kotlin DSL block",
    silent_on="ignoringRequestMatchers(...) scoped to specific paths; files with no HttpSecurity",
    cwe=("CWE-352",),
    references=(
        "https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ),
)

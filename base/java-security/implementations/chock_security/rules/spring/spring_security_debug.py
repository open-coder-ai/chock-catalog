"""Spring Security's debug mode prints the full filter chain and request details to the log --
and its own Javadoc warns it is not for production."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "spring-security-debug"

_GUARD = facts("spring")["security_guard_tokens"]
_FACTS = facts("spring")["security_debug"]
_ANNOTATION_DEBUG = re.compile(_FACTS["annotation_debug"])
_WEB_DEBUG = re.compile(_FACTS["web_debug_call"])

_MESSAGE = (
    "Debug mode logs the full security filter chain and request details for every request -- "
    "Spring Security's own Javadoc says not to use it in production. Remove it, or gate it behind "
    f"a profile that is never active in production; a local-only debugging session needs "
    f"'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """`@EnableWebSecurity(debug = true)`, or `.debug(true)` on a WebSecurity/builder."""
    if not text.holds(*_GUARD):
        return
    for line_no, line in enumerate(text.lines, 1):
        if (_FACTS["annotation"] in line and _ANNOTATION_DEBUG.search(line)) or _WEB_DEBUG.search(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Spring Security debug mode enabled",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(set): @EnableWebSecurity(debug = true), or web.debug(true) "
        "-- logs the full filter chain and request details; not for production"
    ),
    refuses="@EnableWebSecurity(debug = true) and web.debug(true)",
    silent_on="@EnableWebSecurity() with no debug flag, and .debug(false)",
    cwe=("CWE-489", "CWE-215"),
    references=("https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/",),
)

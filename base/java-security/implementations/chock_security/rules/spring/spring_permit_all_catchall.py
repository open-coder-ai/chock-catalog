"""`permitAll()` (or `ignoring()`) on every request removes authorization from the whole app."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "spring-permit-all-catchall"

_GUARD = facts("spring")["security_guard_tokens"]
_FACTS = facts("spring")["permit_all"]
_WILDCARD_PATH = re.compile(_FACTS["wildcard_path"])
_ANY_REQUEST = re.compile(_FACTS["any_request_permit_all"])
_KOTLIN_AUTHORIZE = re.compile(_FACTS["kotlin_authorize_permit_all"])

_MESSAGE = (
    "This permits every request the filter chain sees (or, for web.ignoring(), skips Spring "
    "Security for it entirely), so any endpoint added later inherits no authorization by default. "
    'Match the specific public paths instead, for example requestMatchers("/public/**", '
    '"/actuator/health").permitAll(), and require authentication for anyRequest().'
)


def _matcher_wildcard_permit_all(line: str) -> bool:
    """requestMatchers/antMatchers/mvcMatchers("/**") ... .permitAll() -- one statement, one line."""
    if not any(call in line for call in _FACTS["matcher_calls"]):
        return False
    return bool(_WILDCARD_PATH.search(line)) and _FACTS["permit_all_call"] in line


def _ignoring_wildcard(line: str) -> bool:
    if _FACTS["ignoring_call"] not in line:
        return False
    if not any(call in line for call in _FACTS["matcher_calls"]):
        return False
    return bool(_WILDCARD_PATH.search(line))


def scan(text: FileText) -> Iterator[Finding]:
    """Every catch-all authorization or ignore rule, in a file this security chain configures."""
    if not text.holds(*_GUARD):
        return
    for line_no, line in enumerate(text.lines, 1):
        if (
            _ANY_REQUEST.search(line)
            or _matcher_wildcard_permit_all(line)
            or _KOTLIN_AUTHORIZE.search(line)
            or _ignoring_wildcard(line)
        ):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="permitAll() on every request",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        'never(catchall): anyRequest().permitAll()|requestMatchers("/**").permitAll()|'
        'web.ignoring().requestMatchers("/**") -- match specific public paths instead'
    ),
    refuses='anyRequest()/"/**" matchers passed to permitAll() or web.ignoring(), and the Kotlin DSL form',
    silent_on='a specific public path such as "/public/**" or "/actuator/health"',
    cwe=("CWE-862",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",),
)

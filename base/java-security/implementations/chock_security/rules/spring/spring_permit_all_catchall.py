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
_CHAIN_START = re.compile(_FACTS["chain_start"])
#: `securityMatcher("/api/webhooks/**")` (or the 5.x `antMatcher(...)` on HttpSecurity): the chain
#: sees only those requests, so its anyRequest() means any request *to that path*.
_CHAIN_SCOPE = re.compile(r"\b(?:" + "|".join(_FACTS["chain_scope_calls"]) + r")\s*\(\s*(.*)")
#: How far above the anyRequest() line its chain's scope is looked for, when no bean method is found.
_CHAIN_WINDOW = 30

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


def _scoped_chain(lines: list[str], line_no: int) -> bool:
    """Whether the filter chain this line belongs to is scoped to specific paths: a securityMatcher
    between the chain's bean method and this line, naming no "/**"."""
    start = max(0, line_no - _CHAIN_WINDOW)
    for idx in range(line_no, start - 1, -1):
        if _CHAIN_START.search(lines[idx]):
            start = idx
            break
    for line in lines[start : line_no + 1]:
        scope = _CHAIN_SCOPE.search(line)
        if scope and scope.group(1).strip() and not _WILDCARD_PATH.search(scope.group(1)):
            return True
    return False


def scan(text: FileText) -> Iterator[Finding]:
    """Every catch-all authorization or ignore rule, in a file this security chain configures."""
    if not text.holds(*_GUARD):
        return
    lines = text.lines
    for line_no, line in enumerate(lines, 1):
        any_request = bool(_ANY_REQUEST.search(line) or _KOTLIN_AUTHORIZE.search(line))
        if any_request and _scoped_chain(lines, line_no - 1):
            continue
        if any_request or _matcher_wildcard_permit_all(line) or _ignoring_wildcard(line):
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
    silent_on=(
        'a specific public path such as "/public/**" or "/actuator/health"; anyRequest().permitAll() in a chain '
        'scoped by securityMatcher("/api/webhooks/**") to specific paths'
    ),
    cwe=("CWE-862",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",),
)

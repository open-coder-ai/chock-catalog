"""A wildcard CORS origin with credentials is rejected by the spec; it cannot be correct code."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "java-cors-wildcard-credentials"

_FACTS = facts("java")["cors"]

_MESSAGE = (
    "A wildcard origin together with credentials is refused by every browser and throws at "
    "runtime in Spring 5.3+, so this configuration never does what it looks like it does. Name "
    "the origins that may send credentials, or keep the wildcard and drop credentials. "
    "setAllowedOriginPatterns is the sanctioned form when the origins are not known ahead of time."
)


def _sets_wildcard_origin(line: str) -> bool:
    """A wildcard on an origin setter -- never on a *pattern* setter, which is the safe form."""
    if any(form in line for form in _FACTS["pattern_forms"]):
        return False
    return _FACTS["wildcard"] in line and any(s in line for s in _FACTS["origin_setters"])


def _allows_credentials(text: FileText) -> bool:
    """Credentials are enabled somewhere in this configuration -- absence, so judged per file."""
    return text.holds(*_FACTS["credentials"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every wildcard origin, but only where the same file also turns credentials on."""
    if not _allows_credentials(text):
        return
    for line_no, line in enumerate(text.lines, 1):
        if _sets_wildcard_origin(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Wildcard CORS origin with credentials",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        'never(pair): CORS origin "*" with allowCredentials(true) '
        "-- the spec refuses it; name the origins, or use setAllowedOriginPatterns"
    ),
    refuses="a wildcard origin **with** credentials enabled",
    silent_on="a wildcard alone; a named origin; `setAllowedOriginPatterns`",
)

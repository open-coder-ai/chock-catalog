"""A message-pattern lookup lets whatever a caller puts into a logged string reach the JNDI client,
which is exactly how Log4Shell ran attacker code from a log line nobody thought was executable."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "logging-log4j-lookups"

_FACTS = facts("logging")["log4j_lookups"]

_MESSAGE = (
    "{marker} re-opens message-pattern lookups, which is how Log4Shell turned a logged string "
    "into a JNDI lookup and remote code execution. Log4j 2.15+ disables lookups in the message "
    "by default and needs no such setting; if this is here to turn them back on, remove it. "
    f"'chock: allow {RULE_ID}' on this line if you can show why this is not that."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every line naming a lookup-reopening property, pattern token, or a literal JNDI lookup."""
    for line_no, line in enumerate(text.lines, 1):
        marker = next((m for m in _FACTS["markers"] if m in line), None)
        if marker is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(marker=marker))


RULE = Rule(
    id=RULE_ID,
    pack="logging",
    title="Log4j 2 message-lookup exposure",
    suffixes=(".java", ".kt", ".xml", ".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        'never(configure): log4j2.formatMsgNoLookups=false, a pattern using %m{lookups}/%msg{lookups}, '
        'or a literal "${jndi:" -- Log4j 2.15+ disables message lookups by default; do not turn them back on'
    ),
    refuses='`log4j2.formatMsgNoLookups=false`; `%m{lookups}`/`%msg{lookups}` in a pattern; a literal `${jndi:`',
    silent_on="an ordinary pattern layout with no lookups token; formatMsgNoLookups=true",
)

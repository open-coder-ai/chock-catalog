"""A stack trace or exception message in an error response hands an attacker your package layout,
library versions and, often, the query that failed."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.spring._config import config_pairs, is_spring_config_file

_FACTS = facts("spring")["error_details"]

RULE_ID = "spring-error-details-exposed"

_MESSAGE = (
    "`{key}` set to `{value}` puts {what} into the JSON/HTML error response every client sees. "
    "Leave it at the default (never), and log the detail server-side instead where an operator, "
    "not the caller, reads it."
)


def scan(text: FileText) -> Iterator[Finding]:
    """`include-stacktrace=always|on_param`, or `include-exception=true`, in application config."""
    if not is_spring_config_file(text.path):
        return
    for entry in config_pairs(text):
        value = entry.value.strip().lower()
        if entry.key == _FACTS["stacktrace_key"] and value in _FACTS["stacktrace_values"]:
            message = _MESSAGE.format(key=entry.key, value=entry.value, what="the full stack trace")
            yield Finding(RULE_ID, text.path, entry.line_no, text.lines[entry.line_no - 1], message)
        elif entry.key == _FACTS["exception_key"] and value == "true":
            message = _MESSAGE.format(key=entry.key, value=entry.value, what="the exception's class and message")
            yield Finding(RULE_ID, text.path, entry.line_no, text.lines[entry.line_no - 1], message)


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Stack trace or exception exposed in error responses",
    suffixes=(".properties", ".yml", ".yaml"),
    scan=scan,
    constraint=(
        "never(set): server.error.include-stacktrace=always|on_param, or "
        "server.error.include-exception=true -- log the detail server-side instead"
    ),
    refuses="include-stacktrace=always/on_param, and include-exception=true",
    silent_on="include-stacktrace=never, or the key absent (the framework default)",
)

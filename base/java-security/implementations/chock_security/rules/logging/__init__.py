"""The logging pack: Logging."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.logging.logging_injection import RULE as INJECTION
from chock_security.rules.logging.logging_log4j_lookups import RULE as LOG4J_LOOKUPS
from chock_security.rules.logging.logging_sensitive_data import RULE as SENSITIVE_DATA
from chock_security.rules.logging.logging_stacktrace_to_response import RULE as STACKTRACE_TO_RESPONSE

PACK = Pack(
    id="logging",
    title="Logging",
    covers=(
        "Log4j 2, Logback, SLF4J and java.util.logging: lookups, secrets written to logs, and stack traces sent to the caller."
    ),
)

RULES: tuple[Rule, ...] = (
    LOG4J_LOOKUPS,
    SENSITIVE_DATA,
    STACKTRACE_TO_RESPONSE,
    INJECTION,
)

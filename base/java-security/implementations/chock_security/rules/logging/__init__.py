"""The logging pack: Logging."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="logging",
    title="Logging",
    covers=(
        "Log4j 2, Logback, SLF4J and java.util.logging: lookups, secrets written to logs, and stack traces sent to the caller."
    ),
)

RULES: tuple[Rule, ...] = (
)

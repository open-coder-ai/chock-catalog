"""The exceptions pack: Exception handling."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="exceptions",
    title="Exception handling",
    covers=(
        "Catch, throw and finally: swallowed exceptions, catching Throwable or NullPointerException, control flow escaping finally, causes discarded, over-broad throws clauses."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = ()

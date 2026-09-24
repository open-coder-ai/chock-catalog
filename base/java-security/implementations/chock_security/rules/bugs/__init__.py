"""The bugs pack: Bug patterns."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="bugs",
    title="Bug patterns",
    covers=(
        "Code that compiles and is wrong: identity compared where value was meant, results thrown away, contracts broken between equals and hashCode, arithmetic that overflows or loses precision -- the correctness findings SpotBugs and Sonar report as bugs."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = ()

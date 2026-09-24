"""The testing pack: Tests."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="testing",
    title="Tests",
    covers=(
        "JUnit and TestNG tests that cannot fail or fail at random: tests with no assertion, sleeps, disabled tests with no reason, assertions written backwards or on the wrong API."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = ()

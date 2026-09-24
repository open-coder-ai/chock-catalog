"""The testing pack: Tests."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.testing.testing_assertequals_literal_actual import RULE as ASSERTEQUALS_LITERAL_ACTUAL
from chock_security.rules.testing.testing_assertfalse_equals import RULE as ASSERTFALSE_EQUALS
from chock_security.rules.testing.testing_asserttrue_equality import RULE as ASSERTTRUE_EQUALITY
from chock_security.rules.testing.testing_disabled_without_reason import RULE as DISABLED_WITHOUT_REASON
from chock_security.rules.testing.testing_no_assertion import RULE as NO_ASSERTION
from chock_security.rules.testing.testing_thread_sleep import RULE as THREAD_SLEEP

PACK = Pack(
    id="testing",
    title="Tests",
    covers=(
        "JUnit and TestNG tests that cannot fail or fail at random: tests with no assertion, sleeps, disabled tests with no reason, assertions written backwards or on the wrong API."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = (
    NO_ASSERTION,
    THREAD_SLEEP,
    DISABLED_WITHOUT_REASON,
    ASSERTTRUE_EQUALITY,
    ASSERTFALSE_EQUALS,
    ASSERTEQUALS_LITERAL_ACTUAL,
)

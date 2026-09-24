"""The exceptions pack: Exception handling."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.exceptions.exceptions_catch_broad import RULE as CATCH_BROAD
from chock_security.rules.exceptions.exceptions_catch_npe import RULE as CATCH_NPE
from chock_security.rules.exceptions.exceptions_empty_catch import RULE as EMPTY_CATCH
from chock_security.rules.exceptions.exceptions_finally_control_flow import RULE as FINALLY_CONTROL_FLOW
from chock_security.rules.exceptions.exceptions_generic_thrown import RULE as GENERIC_THROWN
from chock_security.rules.exceptions.exceptions_lost_cause import RULE as LOST_CAUSE

PACK = Pack(
    id="exceptions",
    title="Exception handling",
    covers=(
        "Catch, throw and finally: swallowed exceptions, catching Throwable or NullPointerException, control flow escaping finally, causes discarded, generic exceptions thrown by name."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = (
    EMPTY_CATCH,
    CATCH_BROAD,
    CATCH_NPE,
    FINALLY_CONTROL_FLOW,
    GENERIC_THROWN,
    LOST_CAUSE,
)

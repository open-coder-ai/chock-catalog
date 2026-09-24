"""The bugs pack: Bug patterns."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.bugs.bugs_array_tostring import RULE as ARRAY_TOSTRING
from chock_security.rules.bugs.bugs_bigdecimal_double_constructor import RULE as BIGDECIMAL_DOUBLE_CONSTRUCTOR
from chock_security.rules.bugs.bugs_boolean_assignment_in_condition import RULE as BOOLEAN_ASSIGNMENT_IN_CONDITION
from chock_security.rules.bugs.bugs_equals_non_object_parameter import RULE as EQUALS_NON_OBJECT_PARAMETER
from chock_security.rules.bugs.bugs_equals_without_hashcode import RULE as EQUALS_WITHOUT_HASHCODE
from chock_security.rules.bugs.bugs_ignored_return_value import RULE as IGNORED_RETURN_VALUE
from chock_security.rules.bugs.bugs_integer_division_to_double import RULE as INTEGER_DIVISION_TO_DOUBLE
from chock_security.rules.bugs.bugs_math_abs_of_hashcode_or_random import RULE as MATH_ABS_OF_HASHCODE_OR_RANDOM
from chock_security.rules.bugs.bugs_nan_comparison import RULE as NAN_COMPARISON
from chock_security.rules.bugs.bugs_self_assignment import RULE as SELF_ASSIGNMENT
from chock_security.rules.bugs.bugs_string_identity_comparison import RULE as STRING_IDENTITY_COMPARISON
from chock_security.rules.bugs.bugs_thread_run_instead_of_start import RULE as THREAD_RUN_INSTEAD_OF_START

PACK = Pack(
    id="bugs",
    title="Bug patterns",
    covers=(
        "Code that compiles and is wrong: identity compared where value was meant, results thrown away, contracts broken between equals and hashCode, arithmetic that overflows or loses precision -- the correctness findings SpotBugs and Sonar report as bugs."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = (
    STRING_IDENTITY_COMPARISON,
    EQUALS_WITHOUT_HASHCODE,
    EQUALS_NON_OBJECT_PARAMETER,
    BIGDECIMAL_DOUBLE_CONSTRUCTOR,
    NAN_COMPARISON,
    IGNORED_RETURN_VALUE,
    BOOLEAN_ASSIGNMENT_IN_CONDITION,
    ARRAY_TOSTRING,
    THREAD_RUN_INSTEAD_OF_START,
    SELF_ASSIGNMENT,
    MATH_ABS_OF_HASHCODE_OR_RANDOM,
    INTEGER_DIVISION_TO_DOUBLE,
)

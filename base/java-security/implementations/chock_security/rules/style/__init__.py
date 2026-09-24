"""The style pack: Code style."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.style.style_array_type_style import RULE as ARRAY_TYPE_STYLE
from chock_security.rules.style.style_boolean_literal_comparison import RULE as BOOLEAN_LITERAL_COMPARISON
from chock_security.rules.style.style_constant_name import RULE as CONSTANT_NAME
from chock_security.rules.style.style_empty_statement import RULE as EMPTY_STATEMENT
from chock_security.rules.style.style_multiple_variable_declarations import RULE as MULTIPLE_VARIABLE_DECLARATIONS
from chock_security.rules.style.style_redundant_import import RULE as REDUNDANT_IMPORT
from chock_security.rules.style.style_system_out_println import RULE as SYSTEM_OUT_PRINTLN
from chock_security.rules.style.style_type_name import RULE as TYPE_NAME
from chock_security.rules.style.style_upper_ell import RULE as UPPER_ELL

PACK = Pack(
    id="style",
    title="Code style",
    covers=(
        "The conventions Checkstyle and PMD enforce that a reviewer would otherwise repeat: imports, naming, console output in production code, statement shape."
    ),
    kind="quality",
)

RULES: tuple[Rule, ...] = (
    REDUNDANT_IMPORT,
    SYSTEM_OUT_PRINTLN,
    BOOLEAN_LITERAL_COMPARISON,
    EMPTY_STATEMENT,
    TYPE_NAME,
    CONSTANT_NAME,
    MULTIPLE_VARIABLE_DECLARATIONS,
    UPPER_ELL,
    ARRAY_TYPE_STYLE,
)

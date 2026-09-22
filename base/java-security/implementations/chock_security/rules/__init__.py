"""The rule registry: every rule a pack contributes, keyed by the id a selection names."""

from __future__ import annotations

from chock_security.pack import Rule
from chock_security.rules import (
    java_actuator_exposure,
    java_cors_wildcard,
    java_deserialize_request,
    java_jwt_unverified,
    java_path_traversal,
    java_sqli_mybatis,
    java_unsafe_deserialization,
    java_xss_template,
)

_RULES: tuple[Rule, ...] = (
    java_sqli_mybatis.RULE,
    java_xss_template.RULE,
    java_unsafe_deserialization.RULE,
    java_cors_wildcard.RULE,
    java_actuator_exposure.RULE,
    java_jwt_unverified.RULE,
    java_path_traversal.RULE,
    java_deserialize_request.RULE,
)


def registry() -> dict[str, Rule]:
    """Every rule installed here. A selection may name these ids and no others."""
    return {rule.id: rule for rule in _RULES}

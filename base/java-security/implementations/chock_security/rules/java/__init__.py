"""The java pack: Core Java."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.java import java_unsafe_deserialization
from chock_security.rules.java import java_deserialize_request
from chock_security.rules.java import java_jwt_unverified
from chock_security.rules.java import java_path_traversal

PACK = Pack(
    id="java",
    title="Core Java",
    covers=(
        "The JDK itself, whatever framework sits on top: injection into commands, code, reflection, LDAP and XPath; XML parsers; outbound URLs; archives; file paths; Java and polymorphic deserialization; JWT libraries."
    ),
)

RULES: tuple[Rule, ...] = (
    java_unsafe_deserialization.RULE,
    java_deserialize_request.RULE,
    java_jwt_unverified.RULE,
    java_path_traversal.RULE,
)

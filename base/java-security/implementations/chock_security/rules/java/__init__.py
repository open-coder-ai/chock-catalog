"""The java pack: Core Java."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.java import java_unsafe_deserialization
from chock_security.rules.java import java_deserialize_request
from chock_security.rules.java import java_jwt_unverified
from chock_security.rules.java import java_path_traversal
from chock_security.rules.java import java_command_injection
from chock_security.rules.java import java_code_injection
from chock_security.rules.java import java_unsafe_reflection
from chock_security.rules.java import java_xxe_parser
from chock_security.rules.java import java_xml_decoder
from chock_security.rules.java import java_ssrf_request_url
from chock_security.rules.java import java_zip_slip
from chock_security.rules.java import java_ldap_injection
from chock_security.rules.java import java_xpath_injection

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
    java_command_injection.RULE,
    java_code_injection.RULE,
    java_unsafe_reflection.RULE,
    java_xxe_parser.RULE,
    java_xml_decoder.RULE,
    java_ssrf_request_url.RULE,
    java_zip_slip.RULE,
    java_ldap_injection.RULE,
    java_xpath_injection.RULE,
)

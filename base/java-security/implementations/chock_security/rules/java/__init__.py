"""The java pack: Core Java."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.java import (
    java_code_injection,
    java_command_injection,
    java_deserialize_request,
    java_jwt_unverified,
    java_ldap_injection,
    java_path_traversal,
    java_ssrf_request_url,
    java_unsafe_deserialization,
    java_unsafe_reflection,
    java_xml_decoder,
    java_xpath_injection,
    java_xxe_parser,
    java_zip_slip,
)

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

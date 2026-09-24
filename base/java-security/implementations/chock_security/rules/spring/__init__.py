"""The spring pack: Spring."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.spring import (
    java_actuator_exposure,
    java_cors_wildcard,
    spring_actuator_sensitive_values,
    spring_csrf_disabled,
    spring_devtools_remote,
    spring_error_details_exposed,
    spring_h2_console_remote,
    spring_insecure_session_cookie,
    spring_open_redirect,
    spring_permit_all_catchall,
    spring_plaintext_secret_property,
    spring_security_debug,
    spring_security_headers_disabled,
    spring_session_fixation_disabled,
    spring_spel_injection,
    spring_view_name_injection,
    spring_weak_password_encoder,
)

PACK = Pack(
    id="spring",
    title="Spring",
    covers=(
        "Spring Framework, Boot, Security, Data and Cloud: security filter chains, controllers, SpEL, actuator, and application.properties / application.yml."
    ),
)

RULES: tuple[Rule, ...] = (
    java_cors_wildcard.RULE,
    java_actuator_exposure.RULE,
    spring_csrf_disabled.RULE,
    spring_permit_all_catchall.RULE,
    spring_weak_password_encoder.RULE,
    spring_spel_injection.RULE,
    spring_open_redirect.RULE,
    spring_view_name_injection.RULE,
    spring_plaintext_secret_property.RULE,
    spring_h2_console_remote.RULE,
    spring_error_details_exposed.RULE,
    spring_actuator_sensitive_values.RULE,
    spring_security_debug.RULE,
    spring_session_fixation_disabled.RULE,
    spring_security_headers_disabled.RULE,
    spring_insecure_session_cookie.RULE,
    spring_devtools_remote.RULE,
)

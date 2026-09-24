"""The spring pack: Spring."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.spring import java_cors_wildcard
from chock_security.rules.spring import java_actuator_exposure
from chock_security.rules.spring import spring_csrf_disabled
from chock_security.rules.spring import spring_permit_all_catchall
from chock_security.rules.spring import spring_weak_password_encoder
from chock_security.rules.spring import spring_spel_injection
from chock_security.rules.spring import spring_open_redirect
from chock_security.rules.spring import spring_view_name_injection
from chock_security.rules.spring import spring_plaintext_secret_property
from chock_security.rules.spring import spring_h2_console_remote
from chock_security.rules.spring import spring_error_details_exposed
from chock_security.rules.spring import spring_actuator_sensitive_values
from chock_security.rules.spring import spring_security_debug
from chock_security.rules.spring import spring_session_fixation_disabled
from chock_security.rules.spring import spring_security_headers_disabled
from chock_security.rules.spring import spring_insecure_session_cookie
from chock_security.rules.spring import spring_devtools_remote

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

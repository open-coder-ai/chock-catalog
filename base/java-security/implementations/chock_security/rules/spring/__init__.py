"""The spring pack: Spring."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.spring import java_cors_wildcard
from chock_security.rules.spring import java_actuator_exposure

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
)

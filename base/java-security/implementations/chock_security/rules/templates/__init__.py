"""The templates pack: Templates and views."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.templates import java_xss_template

PACK = Pack(
    id="templates",
    title="Templates and views",
    covers=(
        "Thymeleaf, JSP and JSTL, JSF Facelets, FreeMarker, Velocity, Pebble, Mustache and Handlebars: output escaping and templates built at run time."
    ),
)

RULES: tuple[Rule, ...] = (
    java_xss_template.RULE,
)

"""The jakarta pack: Jakarta EE and other frameworks."""

from __future__ import annotations

from chock_security.pack import Pack, Rule

PACK = Pack(
    id="jakarta",
    title="Jakarta EE and other frameworks",
    covers=(
        "Everything that is not Spring: Servlet, JAX-RS, JSF and web.xml; Struts; Quarkus, Micronaut, Helidon, Vert.x and Dropwizard, and their configuration."
    ),
)

RULES: tuple[Rule, ...] = (
)

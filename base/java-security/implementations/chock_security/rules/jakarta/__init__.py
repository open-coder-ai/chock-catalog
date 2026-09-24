"""The jakarta pack: Jakarta EE and other frameworks."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules.jakarta.jakarta_cors_wildcard_credentials import RULE as CORS_WILDCARD_CREDENTIALS
from chock_security.rules.jakarta.jakarta_directory_listing import RULE as DIRECTORY_LISTING
from chock_security.rules.jakarta.jakarta_forward_request_path import RULE as FORWARD_REQUEST_PATH
from chock_security.rules.jakarta.jakarta_http_method_constraint import RULE as HTTP_METHOD_CONSTRAINT
from chock_security.rules.jakarta.jakarta_insecure_cookie import RULE as INSECURE_COOKIE
from chock_security.rules.jakarta.jakarta_open_redirect import RULE as OPEN_REDIRECT
from chock_security.rules.jakarta.jakarta_security_disabled import RULE as SECURITY_DISABLED
from chock_security.rules.jakarta.jakarta_struts_ognl import RULE as STRUTS_OGNL

PACK = Pack(
    id="jakarta",
    title="Jakarta EE and other frameworks",
    covers=(
        "Everything that is not Spring: Servlet, JAX-RS, JSF and web.xml; Struts; Quarkus, Micronaut, Helidon, Vert.x and Dropwizard, and their configuration."
    ),
)

RULES: tuple[Rule, ...] = (
    OPEN_REDIRECT,
    FORWARD_REQUEST_PATH,
    CORS_WILDCARD_CREDENTIALS,
    DIRECTORY_LISTING,
    HTTP_METHOD_CONSTRAINT,
    STRUTS_OGNL,
    INSECURE_COOKIE,
    SECURITY_DISABLED,
)

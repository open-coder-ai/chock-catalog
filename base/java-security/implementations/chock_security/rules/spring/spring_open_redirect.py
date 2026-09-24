"""A redirect target built from request data lets the caller send a user anywhere, including a
lookalike phishing host the victim trusts because your domain sent them there."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "spring-open-redirect"

_FACTS = facts("spring")["open_redirect"]

_MESSAGE = (
    "This redirect target is built from {source}, so the caller chooses where the browser is sent "
    "-- including an attacker's own host. Check the target against a fixed allowlist of hosts or "
    'paths before redirecting, or require it to start with "/" and not "//" (a same-site path).'
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every redirect sink a Spring controller's method body shows request data reaching."""
    if not text.holds(*_FACTS["guard_tokens"]):
        return
    for flow in flows(text, _FACTS["sinks"], sanitizers=tuple(_FACTS["sanitizers"])):
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, _MESSAGE.format(source=flow.source))


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="Redirect target built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        'never(redirect): "redirect:" + <request data>|new RedirectView(<request data>)|'
        "response.sendRedirect(<request data>) -- check against an allowlist, or require a same-site path"
    ),
    refuses="a redirect: prefix, RedirectView, a Location header, or sendRedirect built from request data",
    silent_on="a target checked against an allowlist or UriComponentsBuilder host, or a same-site startsWith check",
)

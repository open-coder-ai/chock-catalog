"""A redirect target built from request data lets the caller send victims to any host they name."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts
from chock_security.rules.jakarta._config import not_spring

RULE_ID = "jakarta-open-redirect"

_FACTS = facts("jakarta")["redirect"]

_MESSAGE = (
    "This redirect target is built from {source}, so the caller chooses where the browser is "
    "sent next -- a classic open redirect used to dress a phishing link in this site's domain. "
    "Check the target against a fixed allowlist of paths or hosts, or only ever redirect to a "
    f"path you built yourself. A target that must stay dynamic needs 'chock: allow {RULE_ID}' "
    "on this line, justified by the allowlist check that runs before it."
)


def _guarded(text: FileText) -> bool:
    """Only files this pack's frameworks own -- Servlet, JAX-RS, Vert.x or Micronaut."""
    return not_spring(text) and text.holds(*_FACTS["guard_imports"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every redirect call a method body shows request data reaching, in a file this pack owns."""
    if not _guarded(text):
        return
    for flow in flows(text, _FACTS["sinks"], sanitizers=tuple(_FACTS["sanitizers"])):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="jakarta",
    title="Open redirect from request data",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        'never(redirect): sendRedirect|Response.seeOther|.putHeader("Location"|HttpResponse.redirect '
        "built from @QueryParam|@PathParam|request.get* -- check against a fixed allowlist first"
    ),
    refuses="a redirect target a method body shows request data reaching, in a Servlet/JAX-RS/Vert.x/Micronaut file",
    silent_on="a constant redirect target; a target checked against an allowlist first; Spring code",
    cwe=("CWE-601",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",),
)

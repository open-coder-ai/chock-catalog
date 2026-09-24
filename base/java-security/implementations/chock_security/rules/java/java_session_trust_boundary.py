"""A request value stored straight into the session crosses the trust boundary unmarked -- every
later read of that attribute trusts it as if the server, not the caller, had set it."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-session-trust-boundary"

_FACTS = facts("java")["session_trust"]

_MESSAGE = (
    "This session attribute is set from {source} with nothing in between to validate it, so code "
    "that later reads it back off the session trusts a value the caller chose -- a trust boundary "
    "violation. Validate (or look the value up against server-side state) before it reaches "
    f"setAttribute, so the session only ever holds what the server itself decided. A value "
    f"already validated needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every session.setAttribute() a method body shows request data reaching, unvalidated."""
    for flow in flows(text, _FACTS["sinks"]):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Request data stored into the session unvalidated",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(call): session.setAttribute(...) built from @RequestParam|@PathVariable|"
        "request.get* with no validation in between -- check it against server-side state first"
    ),
    refuses="a session.setAttribute() call a method body shows request data reaching",
    silent_on=(
        "a constant or server-derived value (a lookup result, a DB entity); the same value "
        "checked with isValid/allowlist first; a scalar path variable (Long, UUID, ...)"
    ),
    cwe=("CWE-501",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",),
)

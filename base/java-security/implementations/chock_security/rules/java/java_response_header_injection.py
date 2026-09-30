"""Request data written into a response header can carry \\r\\n and forge extra headers or a
second response -- classic HTTP response splitting, whether the sink is a header or a cookie."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-response-header-injection"

_FACTS = facts("java")["header_injection"]

_MESSAGE = (
    "This header (or cookie) value is built from {source}, so the caller can inject \\r\\n and "
    "smuggle in extra headers, a forged Set-Cookie, or a whole second response -- HTTP response "
    "splitting. Strip or reject control characters before the value reaches this call, or encode "
    f"it (URLEncoder.encode) instead of passing it straight through. A value already validated "
    f"needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every setHeader/addHeader/Cookie construction a method body shows request data reaching."""
    for flow in flows(text, _FACTS["sinks"]):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Response header built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(call): response.setHeader|addHeader|new Cookie(...) built from "
        "@RequestParam|@PathVariable|request.get* -- strip control characters or encode the "
        "value first"
    ),
    refuses="a setHeader/addHeader call or a Cookie constructor a method body shows request data reaching",
    silent_on=(
        "a constant header/cookie value; a value validated or encoded before the call; the same "
        "call fed a scalar path variable (Long, UUID, ...) that cannot carry a control character"
    ),
    cwe=("CWE-113",),
    references=("https://owasp.org/www-community/attacks/HTTP_Response_Splitting",),
)

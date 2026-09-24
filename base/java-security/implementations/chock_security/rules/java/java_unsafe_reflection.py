"""Loading a class or method by a name the caller supplied runs whatever code that name reaches."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-unsafe-reflection"

_FACTS = facts("java")["reflection"]

_MESSAGE = (
    "This reflective lookup takes its class or method name from {source}, so the caller decides "
    "which class gets constructed or which method runs, not just which record is fetched. Route "
    "the value through a fixed allowlist -- a map from a validated key to the class or method you "
    "actually intend -- rather than passing it to reflection directly. A lookup that must stay "
    f"dynamic needs 'chock: allow {RULE_ID}' on this line, with that allowlist behind it."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every Class.forName/loadClass/getMethod a method body shows request data reaching."""
    for flow in flows(text, _FACTS["sinks"]):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Reflection driven by request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(load): Class.forName|.loadClass|.getMethod over @RequestParam|@PathVariable|"
        "request.get* -- look the name up in a fixed allowlist rather than handing it to "
        "reflection"
    ),
    refuses="a `Class.forName`, `.loadClass`, or `.getMethod` a method body shows request data reaching",
    silent_on=(
        "a constant class or method name; a name checked against an allowlist before the call; "
        "reflection over a name the application computed itself"
    ),
    cwe=("CWE-470",),
    references=(
        "https://owasp.org/Top10/2021/A08_2021-Software_and_Data_Integrity_Failures/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
    ),
)

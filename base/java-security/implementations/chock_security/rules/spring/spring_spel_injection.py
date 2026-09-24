"""A SpEL expression parsed from request data lets the caller execute arbitrary Java, not just
data lookups -- SpEL can call methods and construct objects, so this is code execution, not a
template."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "spring-spel-injection"

_FACTS = facts("spring")["spel"]

_MESSAGE = (
    "This expression is built from {source} before SpEL parses it, and SpEL can call methods and "
    "construct objects -- a parsed expression is arbitrary code, not a data lookup. Never build "
    "the expression string from request data; if the expression must vary, choose from a fixed set "
    f"of named expressions the request can only pick by key. A parser held at a fixed, "
    f"application-authored expression needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every parseExpression() a method body shows request data reaching, in a file using SpEL."""
    if not text.holds(*_FACTS["guard_tokens"]):
        return
    for flow in flows(text, _FACTS["sinks"]):
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, _MESSAGE.format(source=flow.source))


RULE = Rule(
    id=RULE_ID,
    pack="spring",
    title="SpEL expression built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(parse): SpelExpressionParser().parseExpression(<request data>) "
        "-- SpEL executes; pick from a fixed set of named expressions instead"
    ),
    refuses="parseExpression() where a method body shows request data reaching it",
    silent_on="a constant expression string; files that never mention SpEL's parser types",
    cwe=("CWE-917",),
    references=(
        "https://nvd.nist.gov/vuln/detail/CVE-2022-22963",
        "https://owasp.org/Top10/2021/A03_2021-Injection/",
    ),
)

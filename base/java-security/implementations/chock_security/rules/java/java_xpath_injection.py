"""An XPath expression built from request data lets the caller change which nodes it selects."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-xpath-injection"

_FACTS = facts("java")["xpath"]

_MESSAGE = (
    "This XPath expression is built from {source}, so a value containing \"' or '1'='1\" changes "
    "which nodes the query selects, not just which one it looks up -- an authentication or "
    "authorization bypass in the common case. Bind the value through an XPathVariableResolver "
    "instead of concatenating it into the expression string. An expression that must stay dynamic "
    f"needs 'chock: allow {RULE_ID}' on this line, with that binding in place."
)


def _uses_xpath(text: FileText) -> bool:
    """This rule reads only files that import javax.xml.xpath -- elsewhere `.compile()` and
    `.evaluate()` belong to regexes, templates and countless other APIs this rule has no
    business judging."""
    return text.holds(*_FACTS["imports"])


def _xpath_sink(line: str) -> bool:
    """A file that imports XPath can compile regexes too: `Pattern.compile(` is not an XPath sink."""
    for other in _FACTS["not_xpath"]:
        line = line.replace(other, "")
    return any(sink in line for sink in _FACTS["sinks"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every XPath compile/evaluate a method body shows request data reaching unbound."""
    if not _uses_xpath(text):
        return
    for flow in flows(text, _FACTS["sinks"], sanitizers=tuple(_FACTS["sanitizers"])):
        if not _xpath_sink(flow.line):
            continue
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="XPath expression built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(query): XPath .compile(|.evaluate( over @RequestParam|@PathVariable|"
        "request.get* -- bind the value through XPathVariableResolver rather than concatenating "
        "it into the expression"
    ),
    refuses=(
        "an `XPath.compile()`/`.evaluate()` a method body shows request data reaching unbound, "
        "in a file that imports `javax.xml.xpath`"
    ),
    silent_on=(
        "the same call over a value bound through `XPathVariableResolver`; a constant "
        "expression; `.compile()`/`.evaluate()` in a file with no `javax.xml.xpath` import"
    ),
    cwe=("CWE-643", "CWE-91"),
    references=("https://owasp.org/www-community/attacks/XPATH_Injection",),
)

"""Struts dev-mode, static OGNL access and dynamic method invocation each turn OGNL into RCE."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts
from chock_security.rules.jakarta._config import flat_value

RULE_ID = "jakarta-struts-ognl"

_FACTS = facts("jakarta")["struts"]

_CONFIG_MESSAGE = (
    "This turns on {what}, which lets an OGNL expression in a request reach static methods or "
    "arbitrary value-stack lookups -- the mechanism behind the Struts remote-code-execution CVEs. "
    "Turn it off in production; Struts does not need it to serve requests."
)

_FLOW_MESSAGE = (
    "This value-stack lookup is built from {source}, so the caller supplies the OGNL expression "
    "evaluated against the stack -- arbitrary method calls, not just data reads. Evaluate a fixed "
    "expression, or validate the request value against a strict allowlist before using it."
)

_KEYS = (
    ("devmode_key", "struts.devMode"),
    ("static_access_key", "OGNL static method access"),
    ("dmi_key", "dynamic method invocation"),
)


def _xml_lines(text: FileText) -> Iterator[Finding]:
    """`<constant name="..." value="true"/>` for one of the three dangerous keys."""
    for line_no, line in enumerate(text.lines, 1):
        for fact_key, what in _KEYS:
            key = _FACTS[fact_key]
            if f'name="{key}"' in line and 'value="true"' in line:
                yield Finding(RULE_ID, text.path, line_no, line, _CONFIG_MESSAGE.format(what=what))


def _properties_lines(text: FileText) -> Iterator[Finding]:
    for fact_key, what in _KEYS:
        key = _FACTS[fact_key]
        for line_no, line, value in flat_value(text, key):
            if value == "true":
                yield Finding(RULE_ID, text.path, line_no, line, _CONFIG_MESSAGE.format(what=what))


def _guarded_code(text: FileText) -> bool:
    return text.holds(*_FACTS["code_imports"])


def scan(text: FileText) -> Iterator[Finding]:
    """Struts config that widens OGNL's reach, and OGNL lookups a method body shows request data
    reaching, each only in a file this pack can show is actually Struts."""
    if text.suffix == ".xml" and text.holds(_FACTS["xml_marker"]):
        yield from _xml_lines(text)
        return
    if text.suffix == ".properties" and text.holds(_FACTS["properties_marker"]):
        yield from _properties_lines(text)
        return
    if text.suffix in {".java", ".kt"} and _guarded_code(text):
        for flow in flows(text, _FACTS["ognl_sinks"]):
            message = _FLOW_MESSAGE.format(source=flow.source)
            yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="jakarta",
    title="Struts OGNL exposure",
    suffixes=(".xml", ".properties", ".java", ".kt"),
    scan=scan,
    constraint=(
        "never(enable): struts.devMode|struts.ognl.allowStaticMethodAccess|"
        "struts.enable.DynamicMethodInvocation = true; "
        "never(evaluate): ValueStack.findValue(...) built from request data"
    ),
    refuses="struts.xml/struts.properties turning on dev mode, static access or DMI; a "
    "value-stack lookup a method body shows request data reaching",
    silent_on="those keys left false or absent; a fixed OGNL expression; non-Struts XML/properties",
    cwe=("CWE-917",),
    references=(
        "https://struts.apache.org/security/",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
        "https://owasp.org/Top10/2021/A03_2021-Injection/",
    ),
)

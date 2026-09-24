"""Polymorphic deserialization turns an attacker's type name into a constructed object."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "java-unsafe-deserialization"

_FACTS = facts("java")["deserialization"]

_JACKSON_MESSAGE = (
    "Default typing makes Jackson construct whatever class the incoming JSON names, which is "
    "remote code execution wherever that JSON is not fully trusted. Declare the permitted "
    "subtypes with @JsonSubTypes, or pass a PolymorphicTypeValidator that allowlists them."
)

_XSTREAM_MESSAGE = (
    "This XStream instance never calls an allowlist, so it deserializes any type the document "
    "names. Call allowTypes (or allowTypeHierarchy) with the types this payload may contain "
    "before the first fromXML."
)


def _jackson(text: FileText) -> Iterator[Finding]:
    """Jackson's default typing, which is the call itself rather than a configuration state."""
    tokens = _FACTS["jackson_default_typing"]
    for line_no, line in enumerate(text.lines, 1):
        if any(token in line for token in tokens):
            yield Finding(RULE_ID, text.path, line_no, line, _JACKSON_MESSAGE)


def _xstream(text: FileText) -> Iterator[Finding]:
    """XStream built with no allowlist anywhere in the file -- absence, so judged per file."""
    construction = _FACTS["xstream_construction"]
    if not text.holds(construction):
        return
    if text.holds(*_FACTS["xstream_allowlist_calls"]):
        return
    for line_no, line in enumerate(text.lines, 1):
        if construction in line:
            yield Finding(RULE_ID, text.path, line_no, line, _XSTREAM_MESSAGE)
            return


def scan(text: FileText) -> Iterator[Finding]:
    """Both shapes: the call that enables default typing, and the XStream built without a fence."""
    yield from _jackson(text)
    yield from _xstream(text)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Unsafe polymorphic deserialization",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(enable): jackson activateDefaultTyping|enableDefaultTyping; "
        "never(build): XStream without allowTypes|allowTypeHierarchy"
    ),
    refuses="Jackson default typing; an XStream built with no allowlist",
    silent_on="a plain `ObjectMapper`; an XStream that allowlists",
)

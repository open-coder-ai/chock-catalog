"""XMLDecoder replays its input as Java Bean method calls; the unsafe SnakeYAML forms do the same
by handing the document any class it names, rather than the tag-restricted map/list/scalar SnakeYAML
defaults to."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "java-xml-decoder"

_FACTS = facts("java")["xml_decoder"]

_XMLDECODER_MESSAGE = (
    "XMLDecoder does not parse XML as data -- it replays the document as a sequence of Java "
    "method calls, so whoever wrote the document runs code, not just supplies values. There is no "
    "hardening that makes XMLDecoder safe over input you do not already trust; use a real data "
    f"format (JSON, or plain XML through a real parser) instead. Reading the application's own "
    f"generated output needs 'chock: allow {RULE_ID}' on this line."
)

_SNAKEYAML_MESSAGE = (
    "This Yaml instance is built to construct any class the document names -- Object.class, or "
    "UnsafeConstructor -- rather than the tag-restricted scalars, maps and lists SnakeYAML loads "
    "by default, so a crafted document can instantiate arbitrary types. Construct Yaml with no "
    "argument (safe by default in SnakeYAML 2.x), or pass a Constructor scoped to the one class "
    f"you expect. A document you already trust needs 'chock: allow {RULE_ID}' on this line."
)


def _xmldecoder(text: FileText) -> Iterator[Finding]:
    construction = _FACTS["xmldecoder_construction"]
    for line_no, line in enumerate(text.lines, 1):
        if construction in line:
            yield Finding(RULE_ID, text.path, line_no, line, _XMLDECODER_MESSAGE)


def _snakeyaml(text: FileText) -> Iterator[Finding]:
    """Only the explicit unsafe forms, and only in a file that actually uses SnakeYAML to load --
    SnakeYAML 2.x's plain `new Yaml()` is safe by default and must stay silent."""
    if not text.holds(_FACTS["snakeyaml_import"]) or not text.holds(_FACTS["snakeyaml_load"]):
        return
    for line_no, line in enumerate(text.lines, 1):
        if "new UnsafeConstructor" in line or ("new Yaml(new Constructor(" in line and "Object.class" in line):
            yield Finding(RULE_ID, text.path, line_no, line, _SNAKEYAML_MESSAGE)


def scan(text: FileText) -> Iterator[Finding]:
    """XMLDecoder over any input, plus the explicit unsafe SnakeYAML constructions."""
    yield from _xmldecoder(text)
    yield from _snakeyaml(text)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Arbitrary-execution deserializer (XMLDecoder / unsafe SnakeYAML)",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(construct): new XMLDecoder(; "
        "never(build): new Yaml(new Constructor(Object.class...)) | new UnsafeConstructor "
        "in a file that imports org.yaml.snakeyaml and calls .load "
        "-- neither reads its input as data; construct Yaml with no argument, or a Constructor "
        "scoped to one class"
    ),
    refuses=(
        "`new XMLDecoder(` over any input; `new Yaml(new Constructor(Object.class))` or "
        "`new UnsafeConstructor` in a file that imports SnakeYAML and calls `.load`"
    ),
    silent_on=(
        "`new Yaml()` with no argument; `new Yaml(new Constructor(SomeType.class))`; "
        "`new Yaml(new SafeConstructor())`; a file that never calls `.load`"
    ),
)

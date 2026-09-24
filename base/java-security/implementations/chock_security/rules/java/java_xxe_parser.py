"""An XML parser built with its defaults resolves a document's own DOCTYPE and external entities."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "java-xxe-parser"

_FACTS = facts("java")["xxe"]

_MESSAGE = (
    "This parser is built with its defaults, and this file never hardens it, so a document that "
    "declares a DOCTYPE can pull in external entities -- local files read into the output, or a "
    "request the parser makes on the document's behalf. Disable DOCTYPE declarations "
    "(disallow-doctype-decl / SUPPORT_DTD false), or if a DOCTYPE must be allowed, disable "
    "external entities and set XMLConstants.ACCESS_EXTERNAL_DTD / ACCESS_EXTERNAL_SCHEMA to the "
    f"empty string. A parser over trusted, application-authored XML only needs 'chock: allow "
    f"{RULE_ID}' on this line."
)


def _builds_an_xml_parser(text: FileText) -> bool:
    return text.holds(*_FACTS["factories"])


def _never_hardened(text: FileText) -> bool:
    """Hardening is a file-wide absence, exactly as XStream's allowlist is: the factory and its
    feature calls are rarely on one line, so this is judged over the whole file."""
    return not text.holds(*_FACTS["hardening"])


def scan(text: FileText) -> Iterator[Finding]:
    """Every XML parser factory this file builds, but only where nothing in the file hardens it."""
    if not _builds_an_xml_parser(text) or not _never_hardened(text):
        return
    for line_no, line in enumerate(text.lines, 1):
        if any(factory in line for factory in _FACTS["factories"]):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="XML parser vulnerable to external entities",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(build): DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|"
        "TransformerFactory|SchemaFactory|XMLReaderFactory|SAXReader|SAXBuilder with no "
        "disallow-doctype-decl|external-general-entities|ACCESS_EXTERNAL_DTD|SUPPORT_DTD "
        "hardening anywhere in the file -- a document's DOCTYPE can then reach local files or "
        "make requests on the parser's behalf"
    ),
    refuses=(
        "a `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`/`TransformerFactory`/"
        "`SchemaFactory`/`XMLReaderFactory`/dom4j `SAXReader`/jdom2 `SAXBuilder` this file builds "
        "with no hardening call anywhere in it"
    ),
    silent_on=(
        "the same factory beside `disallow-doctype-decl`, `external-general-entities`, "
        "`XMLConstants.ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA`, `FEATURE_SECURE_PROCESSING`, "
        "or `XMLInputFactory.SUPPORT_DTD`/`IS_SUPPORTING_EXTERNAL_ENTITIES` set false anywhere in "
        "the same file"
    ),
)

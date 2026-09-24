"""$where runs as JavaScript on the server; parsing a joined or request-shaped string lets the
caller add operators the query never intended, not just a value."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "persistence-nosql-injection"

_FACTS = facts("persistence")["nosql"]

_MESSAGE_WHERE = (
    "This $where clause is built by joining {source} into a JavaScript string that MongoDB "
    "evaluates server-side, so the caller can write arbitrary JS, not just a value. Express the "
    "condition with ordinary query operators instead of $where, or bind the value through the "
    f"driver's parameter placeholder rather than joining it in. A $where that must stay dynamic "
    f"needs 'chock: allow {RULE_ID}' on this line."
)

_MESSAGE_PARSE = (
    "This builds a Mongo query/document by parsing {source}, so the caller can add operators "
    "($where, $regex, $gt, ...) the query never intended, not just a value. Build the query with "
    "the driver's typed Query/Criteria/Filters builder instead of parsing a joined or "
    f"request-shaped string. A parse that must stay dynamic needs 'chock: allow {RULE_ID}' on "
    "this line."
)

_STRING = r'"[^"]*"'
_IDENT = r"[A-Za-z_]\w*"
_CONCAT = re.compile(rf"{_STRING}\s*\+\s*({_IDENT})|({_IDENT})\s*\+\s*{_STRING}")
_CONSTANT = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _is_mongo_context(text: FileText) -> bool:
    return text.holds(*_FACTS["context_markers"])


def _concat_identifier(line: str) -> str | None:
    for match in _CONCAT.finditer(line):
        name = match.group(1) or match.group(2)
        if name and not _CONSTANT.match(name):
            return name
    return None


def _where_findings(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(text.lines, 1):
        if _FACTS["where_key"] not in line:
            continue
        ident = _concat_identifier(line)
        if ident is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE_WHERE.format(source=f"`{ident}`"))


def _direct_parse_findings(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(text.lines, 1):
        if not any(sink in line for sink in _FACTS["parse_sinks"]):
            continue
        ident = _concat_identifier(line)
        if ident is not None:
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE_PARSE.format(source=f"`{ident}`"))


def scan(text: FileText) -> Iterator[Finding]:
    """A $where or a query-document parse this file shows built from a joined or request value."""
    if text.suffix not in (".java", ".kt") or not _is_mongo_context(text):
        return
    yield from _where_findings(text)
    reported: set[int] = set()
    for finding in _direct_parse_findings(text):
        reported.add(finding.line_no)
        yield finding
    for flow in flows(text, _FACTS["parse_sinks"]):
        if flow.line_no in reported:
            continue
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, _MESSAGE_PARSE.format(source=flow.source))


RULE = Rule(
    id=RULE_ID,
    pack="persistence",
    title="MongoDB query built from a joined or request-shaped string",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(join): mongo $where, new BasicQuery(...)|Document.parse(...)|"
        "BasicDBObject.parse(...)|JSON.parse(...) built with + of a non-constant or reaching "
        "request data -- use the typed query builder or bind the value"
    ),
    refuses=(
        "a `$where` clause joining in a non-constant value with `+`; "
        "`new BasicQuery(`, `Document.parse(`, `BasicDBObject.parse(` or `JSON.parse(` "
        "built by joining in a non-constant, or a method body shows reaching request data"
    ),
    silent_on=(
        "a fixed JSON/document literal; concatenation of literals or ALL_CAPS constants only; "
        "and a file that never imports a MongoDB driver"
    ),
)

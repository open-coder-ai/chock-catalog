"""A file path built from request data lets the caller choose which file, including ../."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-path-traversal-request-data"

_FACTS = facts("java")["flow"]

_MESSAGE = (
    "This path is built from {source}, so the caller chooses which file is opened -- '../' "
    "walks out of the directory you meant. Take the file name only (FilenameUtils.getName, or "
    "Path.getFileName), resolve it against a fixed base, and check the result still starts with "
    f"that base. A path that must stay dynamic needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every filesystem call a method body shows request data reaching unchecked."""
    for flow in flows(text, _FACTS["path_sinks"]):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Path built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(open): a file path built from @RequestParam|@PathVariable|request.get* "
        "-- take getFileName, resolve against a fixed base, check startsWith"
    ),
    refuses="a file path a method body shows request data reaching",
    silent_on="a constant path; a name taken with `getFileName`; a parsed number",
)

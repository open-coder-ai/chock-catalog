"""ObjectInputStream over request data constructs whatever class the bytes name."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-deserialization-request-stream"

_FACTS = facts("java")["flow"]

_MESSAGE = (
    "This ObjectInputStream reads {source}, so the caller names the classes it constructs and "
    "chooses which gadget chain runs -- remote code execution, not a data-integrity problem. "
    "Java serialization has no safe form over untrusted bytes: carry the payload as JSON or "
    "protobuf into a declared type instead. An ObjectInputFilter is a fence, not a fix, and "
    f"still needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every ObjectInputStream a method body shows request data reaching."""
    for flow in flows(text, _FACTS["stream_sinks"]):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Java deserialization of request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(construct): ObjectInputStream over @RequestBody|request.getInputStream "
        "-- the bytes name the classes; carry the payload as JSON into a declared type"
    ),
    refuses="`ObjectInputStream` over request data",
    silent_on="a stream the application opened itself; the same bytes read as JSON",
)

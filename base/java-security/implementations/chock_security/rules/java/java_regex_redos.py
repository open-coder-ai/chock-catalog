"""A regex pattern built from request data lets the caller choose the pattern, not just what it
matches -- an evil pattern (nested quantifiers) makes Pattern.compile()'s own matcher hang."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-regex-redos"

_FACTS = facts("java")["regex_redos"]

_MESSAGE = (
    "This pattern is compiled from {source}, so the caller chooses the regular expression itself, "
    "not just the text it is matched against -- a pattern with nested quantifiers "
    "(e.g. `(a+)+$`) can make the matcher run for a very long time on ordinary input, a ReDoS. "
    "Choose the pattern from a fixed, application-authored set, or wrap the caller's text with "
    f"Pattern.quote() so it is matched literally rather than compiled as a pattern. A pattern "
    f"already restricted to a fixed set needs 'chock: allow {RULE_ID}' on this line."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every Pattern.compile() a method body shows request data reaching as the pattern itself."""
    for flow in flows(text, _FACTS["sinks"], sanitizers=tuple(_FACTS["sanitizers"])):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Regex pattern built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(call): Pattern.compile(...) built from @RequestParam|@PathVariable|request.get* "
        "-- choose the pattern from a fixed set, or wrap the value in Pattern.quote() first"
    ),
    refuses="a Pattern.compile() call a method body shows request data reaching as the pattern argument",
    silent_on="the same call fed a constant pattern; a request value wrapped in Pattern.quote() first",
    cwe=("CWE-1333",),
    references=("https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",),
)

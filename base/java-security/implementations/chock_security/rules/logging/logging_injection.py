"""Request data concatenated into a log line can carry \\r\\n, forging extra log entries that
never happened -- the classic log-injection trick for hiding an attack in an audit trail."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "logging-injection"

_FACTS = facts("logging")["logger_calls"]

_MESSAGE = (
    "This log line concatenates in {source}, which can carry \\r\\n and forge extra log entries "
    "that never happened -- classic log injection. Pass the value as a placeholder argument "
    "(log.info(\"...{{}}...\", value)) instead of building the message with '+', or strip control "
    f"characters first. 'chock: allow {RULE_ID}' on this line if this sink is not read back as "
    "structured log lines."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every logger call a method body shows request data reaching by string concatenation."""
    for flow in flows(text, _FACTS["sinks"]):
        if "+" not in flow.line:
            continue
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, _MESSAGE.format(source=flow.source))


RULE = Rule(
    id=RULE_ID,
    pack="logging",
    title="Request data concatenated into a log line",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(concatenate): request data with '+' into a log.info/warn/error/debug/trace call "
        "-- pass it as a {} placeholder argument, or strip control characters first"
    ),
    refuses="a method body showing request data reaching a logger call through string concatenation",
    silent_on="the same value passed as a {} placeholder argument rather than concatenated; a constant message",
    cwe=("CWE-117",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",),
)

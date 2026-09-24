"""Request data reaching a shell hands the caller a command line, not an argument."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.flow import flows
from chock_security.pack import Rule, facts

RULE_ID = "java-command-injection"

_FACTS = facts("java")["command"]

_MESSAGE = (
    "This command is built from {source}, so the caller chooses what the shell runs, not just an "
    "argument's value. Invoke the program directly with a fixed executable and each argument as "
    "its own array element -- never a shell (`sh -c`, `cmd /c`) fed a string you assembled. A "
    f"command that must stay dynamic needs 'chock: allow {RULE_ID}' on this line, with the "
    "argument validated against an allowlist first."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every process launch a method body shows request data reaching."""
    for flow in flows(text, _FACTS["sinks"]):
        message = _MESSAGE.format(source=flow.source)
        yield Finding(RULE_ID, text.path, flow.line_no, flow.line, message)


RULE = Rule(
    id=RULE_ID,
    pack="java",
    title="Command built from request data",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(run): Runtime.getRuntime().exec|new ProcessBuilder|.command( over "
        "@RequestParam|@PathVariable|request.get* -- pass a fixed executable and each argument "
        "as its own array element, never a shell string"
    ),
    refuses="a process launch or `.command()` a method body shows request data reaching",
    silent_on=(
        "a constant command; an argument array built entirely of constants; a value validated "
        "against an allowlist before the launch"
    ),
)

"""System.exit() outside a main method shuts down the whole JVM for whatever else happens to share
this process -- a batch job, a servlet container, a test runner -- for a decision that should have
been a thrown exception or a return value the caller gets to act on."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "resources-system-exit"

_FACTS = facts("resources")["system_exit"]

_MESSAGE = (
    "{call} terminates the entire JVM, taking down whatever else shares this process, and this "
    "call is not in a `static void main(` method. Throw an exception or return an error result "
    f"instead, and let the entry point decide whether to exit. 'chock: allow {RULE_ID}' on this "
    "line if this really is a command-line entry point chock did not recognise."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every exit/halt call whose file shows no `static void main(` -- library code should never
    decide to end the process; only an application's own entry point gets to."""
    if text.holds(_FACTS["main_signature"]):
        return
    for line_no, (raw, blanked) in enumerate(zip(text.lines, code(text), strict=True), 1):
        call = next((c for c in _FACTS["calls"] if c in blanked), None)
        if call is not None:
            yield Finding(RULE_ID, text.path, line_no, raw, _MESSAGE.format(call=call))


RULE = Rule(
    id=RULE_ID,
    pack="resources",
    title="System.exit() called outside a main method",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(call): System.exit(...)|Runtime.getRuntime().exit(...)|Runtime.getRuntime().halt(...) "
        "outside static void main(...) -- throw or return an error instead"
    ),
    refuses="System.exit/Runtime.exit/Runtime.halt in a file that declares no `static void main(`",
    silent_on="the same calls in a file that also declares `static void main(`; a comment or string mentioning System.exit",
    cwe=("CWE-382",),
    references=(
        "https://rules.sonarsource.com/java/RSPEC-1147/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#dm-method-invokes-system-exit-dm-exit",
    ),
)

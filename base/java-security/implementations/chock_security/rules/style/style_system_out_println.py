"""A print to standard out/err in production code cannot be turned off, filtered or shipped to
wherever the logs actually go -- it just clogs the console every time this path runs."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.style._paths import is_test_path
from chock_security.source import code

RULE_ID = "style-system-out-println"

_FACTS = facts("style")

_PRINT = re.compile(rf"(?<![\w.])System\.(?:{'|'.join(_FACTS['print_streams'])})\.print(?:ln)?\(")

_MESSAGE = (
    "This prints straight to the console instead of going through a logger, so it cannot be "
    "turned off, filtered by level, or routed anywhere the logs actually go. Use a logger "
    f"instead; a class whose whole purpose is a console tool needs 'chock: allow {RULE_ID}' here."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every System.out/err.print(ln) call, outside test files and outside a class that has a
    `static void main(` entry point -- a CLI tool's own console output is its product, not a leak."""
    if is_test_path(text.path, _FACTS["test_path"]) or text.holds(_FACTS["main_method_marker"]):
        return
    for line_no, line in enumerate(code(text), 1):
        if _PRINT.search(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="style",
    title="System.out/err used directly",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): System.out.print*/System.err.print* outside tests and outside a main() class -- use a logger",
    refuses="System.out.println/print or System.err.println/print in a production class with no `static void main(`",
    silent_on="the same call in a test file; a class with a `static void main(` entry point; `// System.out.println(...)` in a comment",
    references=(
        "https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html#systemprintln",
        "https://rules.sonarsource.com/java/RSPEC-106/",
    ),
)

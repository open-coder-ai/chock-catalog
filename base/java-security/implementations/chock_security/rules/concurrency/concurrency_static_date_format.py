"""SimpleDateFormat, DecimalFormat and Calendar mutate internal state on every parse()/format()
call. A static field shares one instance across every thread and every concurrent request, so two
requests formatting at once corrupt each other's in-progress result -- final does not help,
because it only stops the field from being reassigned, not the object it points to from being
mutated."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "concurrency-static-date-format"

_TYPES = facts("concurrency")["static_date_format"]["types"]

_FIELD_DECL = re.compile(
    r"^\s*((?:(?:public|private|protected|final|static)\s+)*)(" + "|".join(_TYPES) + r")\s+(\w+)\s*[=;]"
)

_MESSAGE = (
    "{name} is a static {type_name}, shared by every thread and every concurrent request. "
    "{type_name} mutates its own internal state on every parse()/format() call, so two threads "
    "using {name} at once corrupt each other's in-progress result -- 'final' does not help here, "
    "it only stops the field being reassigned, not the object it points to being mutated. Make it "
    "an instance field, wrap it in a ThreadLocal, or use DateTimeFormatter (immutable and thread-safe)."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every static field typed SimpleDateFormat/DateFormat/MessageFormat/DecimalFormat/Calendar."""
    for line_no, line in enumerate(code(text), 1):
        match = _FIELD_DECL.match(line)
        if not match or "static" not in match.group(1).split():
            continue
        message = _MESSAGE.format(name=match.group(3), type_name=match.group(2))
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], message)


RULE = Rule(
    id=RULE_ID,
    pack="concurrency",
    title="Static SimpleDateFormat/DateFormat/Calendar field",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(declare): static SimpleDateFormat|DateFormat|MessageFormat|DecimalFormat|Calendar "
        "field -- these mutate on every call and are not thread-safe; use an instance field, a "
        "ThreadLocal, or DateTimeFormatter"
    ),
    refuses="a static (with or without final) field typed SimpleDateFormat, DateFormat, MessageFormat, DecimalFormat or Calendar",
    silent_on="the same types as an instance field or a local variable; a static DateTimeFormatter field (immutable)",
    cwe=("CWE-567",),
    references=(
        "https://rules.sonarsource.com/java/RSPEC-2885/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#stcal-static-dateformat-stcal-static-simple-date-format-instance",
    ),
)

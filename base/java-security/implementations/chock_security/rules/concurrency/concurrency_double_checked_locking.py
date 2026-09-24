"""The classic broken double-checked-locking idiom: check null, lock, check null again, then
assign. Without `volatile`, the JIT and the CPU are both free to reorder the constructor's writes
after the field assignment becomes visible -- a second thread can read a non-null reference to a
half-constructed object."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "concurrency-double-checked-locking"

_NULL_CHECK = re.compile(r"\bif\s*\(\s*(\w+)\s*==\s*null\s*\)")
_SYNCHRONIZED = re.compile(r"\bsynchronized\s*\(")
_WINDOW = 12

_MESSAGE = (
    "This is the classic broken double-checked-locking idiom: check {field} for null, lock, "
    "check {field} again, then assign. Without 'volatile' on {field}, a second thread can "
    "observe a non-null reference to a half-constructed object -- the JIT and the CPU are both "
    "free to reorder the constructor's writes after the field becomes visible. Declare {field} "
    "volatile, or drop the double-checked form and synchronize the whole accessor."
)


def _second_check(window: list[str], name: str) -> int | None:
    for offset, line in enumerate(window):
        match = _NULL_CHECK.search(line)
        if match and match.group(1) == name:
            return offset
    return None


def _is_volatile(text: FileText, name: str) -> bool:
    pattern = re.compile(rf"\bvolatile\b[^;{{]*\b{re.escape(name)}\b\s*[=;]")
    return any(pattern.search(line) for line in code(text))


def scan(text: FileText) -> Iterator[Finding]:
    """Every double null-check around a `synchronized` block on a field that isn't volatile."""
    lines = code(text)
    for line_no, line in enumerate(lines):
        first = _NULL_CHECK.search(line)
        if not first:
            continue
        name = first.group(1)
        window = lines[line_no + 1 : line_no + 1 + _WINDOW]
        if not any(_SYNCHRONIZED.search(w) for w in window):
            continue
        second_offset = _second_check(window, name)
        if second_offset is None or _is_volatile(text, name):
            continue
        found_line = line_no + 1 + second_offset
        yield Finding(RULE_ID, text.path, found_line + 1, text.lines[found_line], _MESSAGE.format(field=name))


RULE = Rule(
    id=RULE_ID,
    pack="concurrency",
    title="Double-checked locking on a non-volatile field",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(pattern): if (x == null) { synchronized (...) { if (x == null) { x = ...; } } } "
        "unless x is volatile -- otherwise a thread can see a non-null, half-constructed x"
    ),
    refuses="the null/synchronized/null-again/assign idiom on a field never declared volatile",
    silent_on="the same idiom when the field is declared volatile; a single null check with no synchronized block",
    cwe=("CWE-609",),
    references=(
        "https://rules.sonarsource.com/java/RSPEC-2168/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#dc-possible-double-check-of-field-dc-doublecheck",
    ),
)

"""equals() and hashCode() are a pair: HashMap/HashSet bucket by hashCode() first, then narrow with
equals(). Override only one and equal objects can land in different buckets, or vice versa."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "bugs-equals-without-hashcode"

_FACTS = facts("bugs")["equals_hashcode"]

#: A true top-level class declaration -- no leading whitespace, so a nested/inner class (which
#: may legitimately rely on the outer class's identity semantics) never confuses this scan.
_TOP_LEVEL_CLASS = re.compile(r"^(?:(?:public|final|abstract)\s+)*class\s+(\w+)")
_EQUALS = re.compile(r"\bpublic\s+boolean\s+equals\s*\(\s*Object\b")
_HASHCODE = re.compile(r"\bpublic\s+int\s+hashCode\s*\(\s*\)")

_MESSAGE = (
    "This class overrides {defines} but not {missing}. HashMap, HashSet and every other hashed "
    "collection bucket by hashCode() first and only call equals() inside the matching bucket -- "
    "define {missing} too (or generate both together), consistent with the fields {defines} "
    f"compares. 'chock: allow {RULE_ID}' on this line if instances of this class are never put "
    "in a hashed collection."
)


def _class_body(lines: list[str], start: int) -> tuple[int, int] | None:
    """The line range `class` at `start` opens, by brace depth. None if it never opens one."""
    depth = 0
    opened = False
    for line_no in range(start, len(lines)):
        depth += lines[line_no].count("{") - lines[line_no].count("}")
        if "{" in lines[line_no]:
            opened = True
        if opened and depth <= 0:
            return start, line_no
    return None


def _flag(lines: list[str], start: int, end: int) -> tuple[int, str] | None:
    """The line and message for a class whose equals()/hashCode() pair is incomplete, or None."""
    body = "\n".join(lines[start : end + 1])
    has_equals = bool(_EQUALS.search(body))
    has_hashcode = bool(_HASHCODE.search(body))
    if has_equals == has_hashcode:
        return None
    defines, missing, pattern = (
        ("equals()", "hashCode()", _EQUALS) if has_equals else ("hashCode()", "equals()", _HASHCODE)
    )
    for offset, line in enumerate(lines[start : end + 1]):
        if pattern.search(line):
            return start + offset, _MESSAGE.format(defines=defines, missing=missing)
    return None


def scan(text: FileText) -> Iterator[Finding]:
    """Every top-level class defining exactly one of equals(Object)/hashCode()."""
    lines = code(text)
    if text.holds(_FACTS["lombok_marker"]):
        return  # Lombok's @EqualsAndHashCode generates both together.
    line_no = 0
    while line_no < len(lines):
        match = _TOP_LEVEL_CLASS.match(lines[line_no])
        if not match:
            line_no += 1
            continue
        span = _class_body(lines, line_no)
        if span is None:
            line_no += 1
            continue
        start, end = span
        flagged = _flag(lines, start, end)
        if flagged:
            found_line, message = flagged
            yield Finding(RULE_ID, text.path, found_line + 1, text.lines[found_line], message)
        line_no = end + 1


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="equals() overridden without hashCode(), or hashCode() without equals()",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(define): public boolean equals(Object o) without public int hashCode(), or the "
        "reverse, in the same top-level class -- define both together (or neither)"
    ),
    refuses="a top-level class overriding only equals(Object) or only hashCode()",
    silent_on="a class overriding both, or neither; @EqualsAndHashCode; records and enums (generated)",
    cwe=("CWE-581",),
    references=(
        "https://rules.sonarsource.com/java/RSPEC-1206/",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#he-class-defines-equals-but-not-hashcode-he-equals-no-hashcode",
    ),
)

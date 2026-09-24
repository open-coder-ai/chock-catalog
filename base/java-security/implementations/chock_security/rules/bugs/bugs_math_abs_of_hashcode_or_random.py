"""Math.abs(Integer.MIN_VALUE) is Integer.MIN_VALUE -- a negative number, because two's-complement
has no positive counterpart for it. hashCode() and nextInt() both range over every int value, so
about one in four billion calls slips this "always positive" trick a negative result anyway."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-math-abs-of-hashcode-or-random"

_ABS_HASHCODE = re.compile(r"Math\.abs\(\s*[\w.]*\.hashCode\(\s*\)\s*\)")
_ABS_RANDOM_INT = re.compile(r"Math\.abs\(\s*[\w.]*\.nextInt\(\s*\)\s*\)")

_MESSAGE = (
    "Math.abs() on {source} can still return a negative number: if {source} happens to be "
    "Integer.MIN_VALUE, Math.abs(Integer.MIN_VALUE) is Integer.MIN_VALUE itself (two's-complement "
    "has no positive counterpart for it), and both hashCode() and nextInt() range over every int "
    "value. Use a bounded random call (Random.nextInt(bound)) or mask/rehash instead of Math.abs()."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every Math.abs() wrapped directly around a .hashCode() or a zero-arg .nextInt() call."""
    for line_no, line in enumerate(code(text), 1):
        if _ABS_HASHCODE.search(line):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(source="a hashCode()"))
        elif _ABS_RANDOM_INT.search(line):
            yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(source="a random int"))


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="Math.abs() of a hashCode() or a random int",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(call): Math.abs(x.hashCode()) | Math.abs(random.nextInt()) -- both can still be Integer.MIN_VALUE, which stays negative under Math.abs()",
    refuses="Math.abs(anything.hashCode()); Math.abs(anything.nextInt())",
    silent_on="Math.abs(x); Math.abs(random.nextInt(bound)); random.nextInt(bound) without Math.abs()",
    references=(
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#rv-bad-attempt-to-compute-absolute-value-of-signed-32-bit-hashcode-rv-absolute-value-of-hashcode",
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#rv-bad-attempt-to-compute-absolute-value-of-signed-random-integer-rv-absolute-value-of-random-int",
    ),
)

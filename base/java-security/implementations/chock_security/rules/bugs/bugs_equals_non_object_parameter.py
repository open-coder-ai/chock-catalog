"""A method named `equals` that does not take `Object` overloads `Object.equals` instead of
overriding it: the JVM calls the real, inherited `equals(Object)` through every collection and
`==`-adjacent API, and this method is dead code that nothing polymorphic ever reaches."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.source import code

RULE_ID = "bugs-equals-non-object-parameter"

#: A single-parameter public `equals` whose parameter type is not `Object`. Multi-parameter
#: `equals` methods are a different (and rarer) shape this rule leaves alone.
_EQUALS_OTHER = re.compile(r"\bpublic\s+boolean\s+equals\s*\(\s*(\w+(?:<[^()]*>)?)\s+\w+\s*\)")

_MESSAGE = (
    "public boolean equals({param_type} ...) does not override Object.equals(Object) -- it "
    "overloads it. Every collection, == comparison and framework that calls equals() through a "
    "polymorphic Object reference still reaches the inherited Object.equals() (identity "
    "comparison), and this method is dead code. Change the parameter to Object and add "
    f"@Override, checking 'instanceof {{param_type}}' inside the method body. 'chock: allow "
    f"{RULE_ID}' on this line if this is a deliberate type-safe helper kept beside the real "
    "equals(Object)."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every `public boolean equals(<non-Object> x)` -- an overload, never an override."""
    for line_no, line in enumerate(code(text), 1):
        match = _EQUALS_OTHER.search(line)
        if not match or match.group(1) in ("Object", "java.lang.Object"):
            continue
        yield Finding(RULE_ID, text.path, line_no, text.lines[line_no - 1], _MESSAGE.format(param_type=match.group(1)))


RULE = Rule(
    id=RULE_ID,
    pack="bugs",
    title="equals() overload instead of override",
    suffixes=(".java",),
    scan=scan,
    constraint=(
        "never(define): public boolean equals(NotObject x) -- overloads Object.equals(Object) "
        "instead of overriding it; take Object and check instanceof inside"
    ),
    refuses="public boolean equals(<Type> x) where Type is not Object",
    silent_on="public boolean equals(Object o); a private/package helper not named equals",
    references=(
        "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html"
        "#eq-equals-method-defined-that-doesn-t-override-equals-object-eq-other-no-object",
    ),
)

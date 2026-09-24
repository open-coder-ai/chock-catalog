"""Every other class in the JDK and every framework on top of it is UpperCamelCase; a type that
breaks the pattern makes a reader stop and wonder if it is a constant or a package instead."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.source import code

RULE_ID = "style-type-name"

_FACTS = facts("style")
_TYPE_DECL = re.compile(r"(?<!@)\b(?:" + "|".join(_FACTS["type_keywords"]) + r")\s+([A-Za-z_$][\w$]*)")
_UPPER_CAMEL = re.compile(r"^[A-Z][A-Za-z0-9]*$")

_MESSAGE = (
    "{name} does not start with an upper-case letter followed by letters and digits only, the "
    "UpperCamelCase every class, interface, enum and record in this codebase otherwise uses. Rename it."
)


def scan(text: FileText) -> Iterator[Finding]:
    for line_no, line in enumerate(code(text), 1):
        for match in _TYPE_DECL.finditer(line):
            name = match.group(1)
            if not _UPPER_CAMEL.match(name):
                yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(name=name))


RULE = Rule(
    id=RULE_ID,
    pack="style",
    title="Type name not UpperCamelCase",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(name): class/interface/enum/record not matching ^[A-Z][A-Za-z0-9]*$",
    refuses="`class userService`, `interface http_client`, `enum status_Code`, `record order_id(...)`",
    silent_on="`class UserService`, `interface HttpClient`, `enum StatusCode`, `record OrderId(...)`; `@interface MyAnnotation` (a different declaration kind)",
    references=("https://checkstyle.org/checks/naming/typename.html", "https://rules.sonarsource.com/java/RSPEC-101/"),
)

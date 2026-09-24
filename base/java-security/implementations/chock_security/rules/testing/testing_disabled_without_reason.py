"""A disabled test with no reason leaves the next person to find it no way to tell whether it is
safe to delete, still tracking a real bug, or was turned off by accident and forgotten."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts
from chock_security.rules.testing._util import is_test_path

RULE_ID = "testing-disabled-without-reason"

_FACTS = facts("testing")
_DISABLED = re.compile(
    r"@(?:" + "|".join(a.lstrip("@") for a in _FACTS["disabled_annotations"]) + r")\b\s*(\(([^)]*)\))?"
)

_MESSAGE = (
    "{annotation} carries no reason, so nobody reading this later knows why the test is off or "
    'when it is safe to turn back on. Add one: {annotation}("why, and what would re-enable it").'
)


def scan(text: FileText) -> Iterator[Finding]:
    if not is_test_path(text.path, _FACTS["test_path"]):
        return
    # This rule is about the reason string's own content, so it reads the raw line -- code()
    # would blank exactly the text this rule needs to look inside.
    for line_no, line in enumerate(text.lines, 1):
        if line.lstrip().startswith("//"):
            continue
        match = _DISABLED.search(line)
        if not match:
            continue
        reason = (match.group(2) or "").strip().strip('"').strip()
        if reason:
            continue
        yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(annotation=match.group(0).split("(")[0]))


RULE = Rule(
    id=RULE_ID,
    pack="testing",
    title="Disabled test with no reason",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint='never(write): @Disabled or @Ignore with no reason string -- always @Disabled("why")',
    refuses="bare `@Disabled`, `@Disabled()`, bare `@Ignore`, `@Ignore()`",
    silent_on='`@Disabled("flaky, see JIRA-123")`; `@Ignore("pending API fix")`; an enabled test; `// @Disabled` in a comment',
    references=("https://rules.sonarsource.com/java/RSPEC-1607/",),
)

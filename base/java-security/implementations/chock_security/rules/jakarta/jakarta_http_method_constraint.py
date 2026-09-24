"""A security-constraint scoped to listed HTTP methods leaves every other verb unprotected."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "jakarta-http-method-constraint"

_FACTS = facts("jakarta")["http_method_constraint"]

_MESSAGE = (
    "This web-resource-collection lists specific HTTP methods, so only those verbs are checked "
    "by the security-constraint -- a request using any other verb (TRACE, PATCH, a custom one) "
    "reaches the resource unauthenticated. Either list every verb this resource must never allow "
    "unauthenticated with <http-method-omission>, or drop the <http-method> list so the "
    "constraint covers every method."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Each web-resource-collection that names methods without an omission list."""
    method_line: int | None = None
    has_omission = False
    inside = False
    for line_no, line in enumerate(text.lines, 1):
        stripped = line.strip()
        if _FACTS["collection_open"] in stripped:
            inside, method_line, has_omission = True, None, False
            continue
        if not inside:
            continue
        if _FACTS["collection_close"] in stripped:
            if method_line is not None and not has_omission:
                yield Finding(RULE_ID, text.path, method_line, text.lines[method_line - 1], _MESSAGE)
            inside = False
            continue
        if _FACTS["omission_tag"] in stripped:
            has_omission = True
        elif _FACTS["method_tag"] in stripped and method_line is None:
            method_line = line_no


RULE = Rule(
    id=RULE_ID,
    pack="jakarta",
    title="HTTP method constraint scoped to listed verbs",
    suffixes=(".xml",),
    scan=scan,
    constraint=(
        "never(scope): <web-resource-collection> with <http-method> and no <http-method-omission> "
        "-- unlisted verbs bypass the constraint; use <http-method-omission> or list none"
    ),
    refuses="a web-resource-collection naming <http-method> with no <http-method-omission>",
    silent_on="<http-method-omission>; a collection with no method list at all (covers every verb)",
    cwe=("CWE-862",),
    references=("https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",),
)

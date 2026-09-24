"""An include whose path the caller names lets them pull in and render any file the server can read."""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "templates-include-request-path"

_FACTS = facts("templates")["include_request_path"]

_MESSAGE = (
    "This include takes its path from the request, so the caller chooses which file gets pulled "
    "in and rendered -- including one the application never meant to serve. Include a fixed path, "
    "or take the caller's choice as a key into a fixed allowlist of fragment names rather than a "
    f"path. An include that must stay dynamic needs 'chock: allow {RULE_ID}' on this line and an "
    "allowlist behind it."
)


def scan(text: FileText) -> Iterator[Finding]:
    """Every include/import/fragment directive this markup builds from a request parameter."""
    for line_no, line in enumerate(text.lines, 1):
        if any(token in line for token in _FACTS["tokens"]):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="templates",
    title="Template include path taken from the request",
    suffixes=(".jsp", ".jspx", ".tag", ".html", ".xhtml"),
    scan=scan,
    constraint=(
        'never(include): <jsp:include page="<%= request.getParameter|'
        '<c:import url="${param.|<jsp:include page="${param.|'
        'th:replace="${param.|th:insert="${param.|~{${param. '
        "-- include a fixed path, or key an allowlist by the caller's choice"
    ),
    refuses=(
        '`<jsp:include page="<%= request.getParameter...`, `<c:import url="${param....`, '
        '`<jsp:include page="${param....`, Thymeleaf `th:replace="${param....`/'
        '`th:insert="${param....`/`~{${param....` fragment expressions'
    ),
    silent_on="a constant include path, and `param`/request use that is not the include path itself",
    cwe=("CWE-829", "CWE-73"),
    references=("https://owasp.org/www-community/attacks/Path_Traversal",),
)

"""A stack trace sent to the caller hands them your package layout, library versions and file
paths -- a map of the attack surface that the response was never meant to disclose."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule, facts

RULE_ID = "logging-stacktrace-to-response"

_FACTS = facts("logging")["stacktrace_response"]

_PRINT_TO_WRITER = re.compile(r"\.printStackTrace\(\s*[\w.]*getWriter\(\)\s*\)")
_WRITE_EXCEPTION = re.compile(
    r"getWriter\(\)\.(?:write|print)\([^)]*(?:getMessage\(\)|getStackTrace\(\)|"
    r"ExceptionUtils\.getStackTrace\()"
)
_BODY_EXCEPTION = re.compile(r"\.body\([^)]*(?:getStackTrace\(\)|ExceptionUtils\.getStackTrace\()")

_MESSAGE = (
    "This sends the exception's own detail -- a stack trace or its message -- straight into the "
    "response body, disclosing package layout, library versions and file paths to whoever made "
    "the request. Log the exception server-side and return a generic error with a correlation id "
    f"instead. 'chock: allow {RULE_ID}' on this line if this response never leaves a trusted "
    "operator tool."
)


def scan(text: FileText) -> Iterator[Finding]:
    """A stack trace or exception detail written into the HTTP response the caller receives."""
    for line_no, line in enumerate(text.lines, 1):
        if _PRINT_TO_WRITER.search(line) or _WRITE_EXCEPTION.search(line) or _BODY_EXCEPTION.search(line):
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE)


RULE = Rule(
    id=RULE_ID,
    pack="logging",
    title="Stack trace or exception detail sent to the caller",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint=(
        "never(write): e.printStackTrace(response.getWriter()), getWriter().write/print of "
        "getMessage()/getStackTrace()/ExceptionUtils.getStackTrace(), or a response body built "
        "from either -- log server-side and return a generic error with a correlation id"
    ),
    refuses=(
        "printStackTrace(response.getWriter()); response.getWriter().write/print of "
        "e.getMessage()/e.getStackTrace()/ExceptionUtils.getStackTrace(e); a .body(...) built from either"
    ),
    silent_on="logging the exception server-side; a response body built from a fixed error message or an error code",
)

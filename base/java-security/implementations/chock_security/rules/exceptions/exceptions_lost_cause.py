"""Wrapping a caught exception in a new one without passing the original along drops its stack
trace and cause chain -- the log shows where the wrapper was thrown, never where the failure
actually started, which is exactly the information a debugger needs most."""

from __future__ import annotations

import re
from collections.abc import Iterator

from chock_security.decision import FileText, Finding
from chock_security.pack import Rule
from chock_security.rules.exceptions._catch import catch_clauses

RULE_ID = "exceptions-lost-cause"

_THROW_NEW = re.compile(r"\bthrow\s+new\s+[\w.]+\s*\(")

_MESSAGE = (
    "This creates and throws a new exception inside a catch for `{variable}` without passing "
    "{variable} to it, so the original stack trace and cause chain are lost -- the log will show "
    "only where this new exception was thrown, never where the failure actually started. Pass "
    f"{{variable}} as the cause (`new X(msg, {{variable}})`). 'chock: allow {RULE_ID}' on this "
    "line if the original truly carries nothing worth keeping."
)


def _args(body: str, open_paren: int) -> str | None:
    depth = 0
    for i in range(open_paren, len(body)):
        if body[i] == "(":
            depth += 1
        elif body[i] == ")":
            depth -= 1
            if depth == 0:
                return body[open_paren + 1 : i]
    return None


def _passes_cause(args: str, variable: str) -> bool:
    """Whether one of the constructor's top-level arguments is the caught variable itself."""
    depth, start = 0, 0
    parts = []
    for i, ch in enumerate(args):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(args[start:i])
            start = i + 1
    parts.append(args[start:])
    return any(part.strip() == variable for part in parts)


def _logged(body: str, variable: str) -> bool:
    """Whether the catch hands the exception itself to some call -- a logger, a metrics hook --
    so its stack trace is kept somewhere. Only its message (`e.getMessage()`) does not count."""
    return re.search(rf"[(,]\s*{re.escape(variable)}\s*[,)]", body) is not None


def scan(text: FileText) -> Iterator[Finding]:
    """Every `throw new X(...)` in a catch that neither passes on nor logs the caught exception.

    Sonar's rule is the same: handle the exception by logging it or by rethrowing it as a cause.
    """
    for clause in catch_clauses(text):
        if _logged(clause.code_body, clause.variable):
            continue
        for match in _THROW_NEW.finditer(clause.code_body):
            args = _args(clause.code_body, match.end() - 1)
            if args is None or _passes_cause(args, clause.variable):
                continue
            line_no = clause.line_no + clause.code_body.count("\n", 0, match.start())
            line = text.lines[line_no - 1] if 0 < line_no <= len(text.lines) else ""
            yield Finding(RULE_ID, text.path, line_no, line, _MESSAGE.format(variable=clause.variable))


RULE = Rule(
    id=RULE_ID,
    pack="exceptions",
    title="Caught exception not passed as the new exception's cause",
    suffixes=(".java", ".kt"),
    scan=scan,
    constraint="never(throw): new X(...) inside a catch block without passing the caught exception as an argument -- pass it as the cause",
    refuses='`throw new Y(...)` inside a catch block where none of the constructor arguments is the caught variable itself (e.g. `throw new Y(e.getMessage())` or `throw new Y("message")`)',
    silent_on='`throw new Y(e)`; `throw new Y("message", e)`; `throw e;` rethrowing the original; a catch block that does not throw a new exception',
    references=(
        "https://rules.sonarsource.com/java/RSPEC-1166/",
        "https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html#preservestacktrace",
    ),
)

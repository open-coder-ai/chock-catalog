"""Whether a line's check is applied to request data, read from the code and never the comments.

A sanitizer's name somewhere on a line proves nothing: `// TODO sanitize later`, `"/srv/sanitize/"`
and `sanitize(other)` all hold it. A check counts when it is a call taking the request value, or a
method called on it, in the file's code with comments and literal contents blanked.
"""

from __future__ import annotations

import re

from chock_security.pack import facts
from chock_security.source import blank

_FACTS = facts("java")["flow"]


def mentions(line: str, names: set[str]) -> bool:
    """Whether the line USES one of these names: in its code, never inside a string literal or a
    comment -- `"//item[@sku=$sku]"` names an XPath variable, not the `sku` parameter."""
    code_only = blank(line)
    return any(re.search(rf"\b{re.escape(name)}\b", code_only) for name in names)


def holds(line: str, tokens: list[str]) -> bool:
    return any(token in line for token in tokens)


#: `value.matches(SAFE_NAME)`: validation against a named pattern. `Matcher.matches()`, with nothing
#: between its parentheses, is the match itself -- often the very sink being judged -- never a check.
_VALIDATED = re.compile(r"\.matches\(\s*[A-Z][A-Z0-9_]*\s*\)")


def _opening(code: str, close: int) -> int:
    """Where the bracket closing at `close` was opened; 0 when it was opened on an earlier line."""
    depth = 0
    for index in range(close, -1, -1):
        depth += (code[index] in ")]") - (code[index] in "([")
        if depth == 0:
            return index
    return 0


def _inside(code: str, opening: int) -> str:
    """What sits between the parenthesis at `opening` and its match, or up to the line's end."""
    depth = 0
    for index in range(opening, len(code)):
        depth += (code[index] == "(") - (code[index] == ")")
        if depth == 0:
            return code[opening + 1 : index]
    return code[opening + 1 :]


def _receiver(code: str, dot: int) -> str:
    """The expression a call is made on: `Paths.get(base, name)` for the `.normalize()` after it."""
    start = dot
    while True:
        while start > 0 and code[start - 1] in ")]":
            start = _opening(code, start - 1)
        while start > 0 and (code[start - 1].isalnum() or code[start - 1] in "_$"):
            start -= 1
        if start == 0 or code[start - 1] != ".":
            return code[start:dot]
        start -= 1


def _carries(expression: str, tainted: set[str]) -> bool:
    return holds(expression, _FACTS["source_calls"]) or mentions(expression, tainted)


_CALL_AFTER = re.compile(r"\s*(?:\.\s*\w+\s*)?\(")


def _call_opening(code: str, token: str, match: re.Match[str]) -> int | None:
    """Where the call this token names opens its arguments, or None when it is not called here."""
    if token.endswith("("):
        return match.end() - 1
    end = match.end()
    while end < len(code) and (code[end].isalnum() or code[end] in "_$"):
        end += 1
    call = _CALL_AFTER.match(code, end)
    return call.end() - 1 if call else None


def _applied(code: str, token: str, tainted: set[str]) -> bool:
    """Whether `token` occurs in this code as a check on request data, not merely as a name.

    `.name` tokens are a method called on the value (`name.startsWith(base)`, `x.normalize()`) or
    one taking it (`.is(value)`). Any other token is a call taking it (`FilenameUtils.getName(name)`),
    or the start of the identifier that is (`isValidPath(name)`, `allowlist.get(name)`)."""
    on_value = token.startswith(".")
    for match in re.finditer(re.escape(token), code):
        if on_value and _carries(_receiver(code, match.start()), tainted):
            return True
        if not on_value or token.endswith("("):
            opening = _call_opening(code, token, match)
            if opening is not None and _carries(_inside(code, opening), tainted):
                return True
    return False


def sanitized(code: str, sanitizers: list[str], tainted: set[str]) -> bool:
    """Whether a check in this line's code is applied to request data it carries."""
    if any(_applied(code, token, tainted) for token in sanitizers):
        return True
    return any(_carries(_receiver(code, m.start()), tainted) for m in _VALIDATED.finditer(code))

"""A normalized path is a check only once it is held to its base: `normalize()` alone leaves `../`.

`base.resolve(name).normalize()` still starts with whatever `name` climbed out to; what keeps a path
inside a directory is `p.startsWith(base)` on the normalized value. A variable assigned from a
normalizing call (`normalize()`, `toRealPath(`, `getCanonicalPath()`) keeps carrying the request data
until a later line tests that same variable with `startsWith` in a condition: an `if`, a loop, or an
assertion or precondition call.
"""

from __future__ import annotations

import re

from chock_security.sanitizer import closing, sink_regions, statement_end

ASSIGNMENT = re.compile(r"(?:^|[^=!<>+\-*/%&|^])(\w+)\s*=(?!=)")

#: A value that ends in a call resolving it to a form `startsWith` can hold to a base, as a path or
#: its string. `normalize().resolve(name)` ends in another resolve and is not one.
_NORMALIZED = re.compile(
    r"\.\s*(?:normalize\s*\(\s*\)|toRealPath\s*\([^()]*\)|getCanonical(?:Path|File)\s*\(\s*\))"
    r"(?:\s*\.\s*(?:toString|toFile|toPath)\s*\(\s*\))?\s*$"
)

#: Where a condition opens: the call whose parentheses hold the containment test.
_CONDITION = re.compile(
    r"(?<![\w$])(?:if|while)\s*\(|(?<![\w$])(?:check\w*|require\w*|verify\w*|isTrue|assertTrue)\s*\("
)
_ASSERT = re.compile(r"(?<![\w$])assert\s")

#: `startsWith` taking a base: `startsWith("")` is true of every path and holds it to nothing.
#: Literals read blanked: a non-empty one is quotes around spaces, an empty one two adjacent quotes.
_STARTS_WITH = r"\s*\.\s*startsWith\s*\(\s*(?!(?:\"\"|'')\s*\))[^\s)]"


def _normalizes(value: str) -> bool:
    return _NORMALIZED.search(value.strip()) is not None


def _in_condition(code: str, start: int) -> bool:
    if _ASSERT.search(code, 0, start):
        return True
    return any(match.end() <= start <= closing(code, match.end() - 1) for match in _CONDITION.finditer(code, 0, start))


def contained(code: str, name: str) -> bool:
    """Whether this line tests `name` against a base in a condition."""
    pattern = re.compile(rf"(?<![\w$.]){re.escape(name)}{_STARTS_WITH}")
    return any(_in_condition(code, match.start()) for match in pattern.finditer(code))


def deferred_to(line: str, code: str, sinks: list[str]) -> str | None:
    """The variable a sink on this line only builds, as `Path p = Paths.get(base, name).normalize();`:
    the path is refused unless a later line holds `p` to its base. None for any other line."""
    match = ASSIGNMENT.search(code)
    if match is None or not _normalizes(code[match.end() : statement_end(code, match.end())]):
        return None
    inside = all(start >= match.end() for start, _ in sink_regions(line, code, sinks))
    return match.group(1) if inside else None


def hold_to_base(code: str, tainted: set[str], normalized: set[str]) -> set[str]:
    """Track the variables holding a normalized path, and clear those this line holds to a base.
    Returns the variables cleared."""
    for match in ASSIGNMENT.finditer(code):
        if _normalizes(code[match.end() : statement_end(code, match.end())]):
            normalized.add(match.group(1))
        else:
            normalized.discard(match.group(1))
    cleared = {name for name in normalized if contained(code, name)}
    normalized -= cleared
    tainted -= cleared
    return cleared

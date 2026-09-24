"""Compares Maven/Gradle version strings, and resolves the property references they carry.

A version comparison here decides whether a rule fires on real code, so it has to survive the
shapes dependency versions actually take: a plain `2.14.1`, a pre-release `2.17.0-rc1`, a
`5.3.18.RELEASE` whose trailing word means nothing, and a `${log4j.version}` or `$log4jVersion`
that only resolves by reading the same file's own `<properties>` or `ext`/`val` declarations.
Anything this cannot resolve with confidence returns None, and a rule reading that stays silent
-- a guess here is a false positive, which this whole pack exists to avoid.
"""

from __future__ import annotations

import re

from chock_security.decision import FileText

#: A trailing qualifier that means "no qualifier": Maven and OSGi both spell a plain release
#: this way at the end of a version string, and it must not be read as a pre-release marker.
_RELEASE_QUALIFIERS = {"release", "final", "ga", "sec01", "sec02"}

#: Known pre-release qualifiers, ranked older (lower) to newer (higher), all below a release.
_PRERELEASE_ORDER = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "milestone": 2,
    "m": 2,
    "cr": 3,
    "rc": 3,
}

_TOKEN = re.compile(r"[0-9]+|[A-Za-z]+")


def _segment(token: str) -> tuple[int, int, str]:
    """One dot/dash-separated piece, ranked so a release always outranks a pre-release."""
    if token.isdigit():
        return (1, int(token), "")
    lower = token.lower()
    if lower in _RELEASE_QUALIFIERS:
        return (1, 0, "")
    if lower in _PRERELEASE_ORDER:
        return (0, _PRERELEASE_ORDER[lower], lower)
    return (0, 99, lower)  # an unknown qualifier: treated as a pre-release, ranked after known ones


def _key(version: str) -> list[tuple[int, int, str]]:
    tokens = _TOKEN.findall(version)
    return [_segment(t) for t in tokens] or [(1, 0, "")]


_PAD = (1, 0, "")  # a missing trailing segment reads as a plain release of that position


def compare(a: str, b: str) -> int:
    """-1, 0 or 1: how `a` orders against `b`, numeric segment by numeric segment."""
    left, right = _key(a), _key(b)
    for i in range(max(len(left), len(right))):
        pa = left[i] if i < len(left) else _PAD
        pb = right[i] if i < len(right) else _PAD
        if pa != pb:
            return -1 if pa < pb else 1
    return 0


def lt(a: str, b: str) -> bool:
    return compare(a, b) < 0


def gte(a: str, b: str) -> bool:
    return compare(a, b) >= 0


#: A Maven property: `<name>value</name>`, its value holding no nested tag or placeholder of
#: its own -- a property whose value is itself `${...}` is chased by `_resolve`, one hop at a
#: time, never guessed past what the same file states.
_POM_PROPERTY = re.compile(r"<([A-Za-z][\w.\-]*)>\s*([^<>{}$]+?)\s*</\1>")

#: A Gradle `ext`/top-level property: `ext.name = 'value'`, `val name = "value"`, `def name = 'value'`,
#: or a bare `name = 'value'` inside an `ext { ... }` block -- all the same shape once the
#: optional keyword and dotted prefix are stripped.
_GRADLE_PROPERTY = re.compile(r"(?:val\s+|var\s+|def\s+|ext\.)?([A-Za-z_]\w*)\s*=\s*['\"]([^'\"]+)['\"]")

_BRACED_REF = re.compile(r"^\$\{\s*([^}]+?)\s*\}$")
_BARE_REF = re.compile(r"^\$([A-Za-z_][\w.]*)$")


def _properties(text: FileText) -> dict[str, str]:
    if text.suffix == ".xml":
        return dict(_POM_PROPERTY.findall(text.text))
    return dict(_GRADLE_PROPERTY.findall(text.text))


def resolve(text: FileText, token: str) -> str | None:
    """The literal version `token` names: itself if it is already literal, else the same file's
    own property table, followed one hop at a time. None when the chain leaves this file, or
    loops, or the property is simply not declared here -- callers must stay silent on None.
    """
    token = token.strip()
    match = _BRACED_REF.match(token) or _BARE_REF.match(token)
    if not match:
        return token
    properties = _properties(text)
    name = match.group(1)
    seen: set[str] = set()
    while True:
        if name in seen or name not in properties:
            return None
        seen.add(name)
        value = properties[name].strip()
        inner = _BRACED_REF.match(value) or _BARE_REF.match(value)
        if not inner:
            return value
        name = inner.group(1)

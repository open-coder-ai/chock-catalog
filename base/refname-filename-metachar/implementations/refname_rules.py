"""Names a shell, a CI step or git can misread (stdlib only; the guard, the script gate and the pre-push hook share it)."""

from __future__ import annotations

import re
import unicodedata

SUBST = "subst"
ADVICE = (
    "Rename it with letters, digits, spaces inside, '.', '_', '-' and '/' only: no segment may start with '-' or end "
    "in a space or '.'. No waiver: if the name is truly required, a person creates it from their own shell."
)
_SUBST = re.compile(r"\$[({'\"]|\$IFS|`")
_OPERATOR = re.compile(r"[;&|<>]")
_DECODE = re.compile(r"base64\W{0,8}-{1,2}d(?:ecode)?(?![a-z])|b64decode|frombase64string", re.IGNORECASE)
# Bidi marks, embeddings, overrides and isolates, by code point so this file never carries one.
_BIDI = frozenset(map(chr, (0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))))
_HEX = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}", re.IGNORECASE)
_REF_PREFIX = re.compile(r"refs/(?:heads|tags)/|refs/remotes/[^/]+/")
_SHOWN = 120


def shown(name: str) -> str:
    """The name with control characters escaped, so printing it cannot move the cursor or hide text."""
    text = name.encode("unicode_escape").decode("ascii")
    return text if len(text) <= _SHOWN else text[:_SHOWN] + "..."


def _segment_problems(name: str, *, dotdot: bool) -> list[tuple[str, str]]:
    found = []
    for segment in name.split("/"):
        if segment in (".", ".."):
            if segment == ".." and dotdot:
                found.append(("dotdot", "a '..' segment"))
            continue
        if segment.startswith("-"):
            found.append(("dash", "a segment starting with '-', which a command reads as an option"))
        if segment.endswith((" ", ".")):
            found.append(("trailing", "a segment ending in a space or '.', which Windows drops"))
    return found


def problems(name: str, *, dotdot: bool = True) -> list[tuple[str, str]]:
    """(code, reason) for each way a path or ref name can be misread; empty when it is plain.

    `dotdot` is off for a command's operands, where `../x` is ordinary navigation, and on for a tracked path or ref.
    """
    found = []
    if any(unicodedata.category(char) == "Cc" or char in _BIDI for char in name):
        found.append(("control", "a control or bidirectional-override character (newline, CR, tab, escape)"))
    if _SUBST.search(name):
        found.append((SUBST, "shell substitution syntax (dollar-paren, dollar-brace, $IFS or a backtick)"))
    if _OPERATOR.search(name):
        found.append(("operator", "a shell operator (; & | < >)"))
    if _DECODE.search(name):
        found.append(("decode", "a base64-decode shape"))
    found += _segment_problems(name, dotdot=dotdot)
    return list(dict.fromkeys(found))


def ref_problems(ref: str) -> list[tuple[str, str]]:
    """problems() for a branch or tag name, plus the shape of a full commit id, which shadows that commit."""
    found = problems(ref)
    prefix = _REF_PREFIX.match(ref)
    if _HEX.fullmatch(ref[prefix.end() :] if prefix else ref):
        found.append(("sha", "the shape of a full commit id, so it shadows that commit wherever the id is resolved"))
    return found


def describe(kind: str, name: str, found: list[tuple[str, str]]) -> str:
    """One refusal line: what was named, why, and the compliant alternative."""
    reasons = "; ".join(reason for _code, reason in found)
    return f"{kind} '{shown(name)}' is refused: it has {reasons}. {ADVICE}"

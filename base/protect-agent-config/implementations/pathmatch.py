"""Globs, variables and unknown text read as patterns over protected paths (stdlib only)."""

from __future__ import annotations

import re
from functools import cache

DYNAMIC = re.compile(r"[*?\[$]")
_VARIABLE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")
_PIECE = re.compile(r"\$(?:\{[^}]*\}|\w+|[@*#?!$-])")


def expand(token: str, env: dict[str, str]) -> str:
    """Replace `$X` and `${X}` that an earlier assignment in the same command line set to a plain value."""

    def value(found: re.Match[str]) -> str:
        known = env.get(found[1] or found[2])
        return found[0] if known is None or DYNAMIC.search(known) else known

    return _VARIABLE.sub(value, token)


def _bracket(body: str) -> str:
    negated = body[:1] in ("!", "^")
    return (
        "[" + ("^" if negated else "") + (body[1:] if negated else body).replace("\\", "\\\\").replace("[", "\\[") + "]"
    )


@cache
def pattern(path: str, *, loose: bool) -> re.Pattern[str]:
    """A glob (`*` `?` `[..]`, never matching `/` or a leading dot) and unknown variable text (anything) as a regex."""
    out, at = ["(?:.*/)?" if loose else ""], 0
    while at < len(path):
        char = path[at]
        if char in "*?[" and (at == 0 or path[at - 1] == "/"):
            out.append(r"(?!\.)")
        piece = _PIECE.match(path, at) if char == "$" else None
        close = path.find("]", at + 2) if char == "[" else -1
        if piece:
            glued = (at > 0 and path[at - 1] != "/") or (piece.end() < len(path) and path[piece.end()] != "/")
            out.append("[^/]*" if glued else ".*")
            at = piece.end()
        elif close > 0:
            out.append(_bracket(path[at + 1 : close]))
            at = close + 1
        else:
            out.append({"*": "[^/]*", "?": "[^/]"}.get(char) or re.escape(char))
            at += 1
    try:
        return re.compile("".join(out), re.DOTALL)
    except re.error:
        return re.compile(".*")


def values(args: list[str]) -> list[str]:
    """Path-like words of an argument list: operands, and the value of `--opt=x` or `-Path:x`."""
    found = []
    for arg in args:
        if not arg.startswith("-"):
            found.append(arg)
        elif "=" in arg or ":" in arg:
            found.append(re.split("[=:]", arg, maxsplit=1)[1])
    return found


def literals(arg: str) -> list[str]:
    """The word itself and each quoted string in it."""
    return [arg, *re.findall(r"""['"]([^'"\s]+)['"]""", arg)]

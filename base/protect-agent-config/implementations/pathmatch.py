"""Globs, variables and unknown text read as patterns over protected paths (stdlib only)."""

from __future__ import annotations

import re
from functools import cache

DYNAMIC = re.compile(r"[*?\[$]")
# What `$(mktemp ...)` becomes: a fresh, randomly named path, which cannot be a protected one.
FRESH = "$__mktemp__"
_VARIABLE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")
_NESTING = 4
_STARS = 6
PIECE = re.compile(r"\$(?:\{[^}]*\}|\w+|[@*#?!$-])")
# A Windows path with a drive letter, as Windows gives the repository folder (`C:\Users\me`) and a path word once its slashes are turned (`C:/Users/me`).
DRIVE = re.compile(r"[A-Za-z]:(?:[\\/]|$)")
DEVICE = re.compile(r"^[\\/]{2}[?.][\\/]")  # Windows spells a drive path as a device: `\\?\C:\x`, `\\.\C:\x`


def expand(token: str, env: dict[str, str], _depth: int = 0) -> str:
    """Replace `$X` and `${X}` that an earlier assignment in the same command line set to a plain value."""

    def value(found: re.Match[str]) -> str:
        name = found[1] or found[2]
        known = env.get(name)
        if known is not None and "$" in known and not known.startswith(FRESH) and _depth < _NESTING:
            known = expand(
                known, {k: v for k, v in env.items() if k != name}, _depth + 1
            )  # `H=$PWD/hooks`: the value too
        fresh = known is not None and known.startswith(FRESH) and not DYNAMIC.search(known[len(FRESH) :])
        return found[0] if known is None or (DYNAMIC.search(known) and not fresh) else known

    return _VARIABLE.sub(value, token)


_POSIX = {
    "alpha": "a-z",
    "upper": "a-z",  # the path is lowercased before it is matched, so upper reads as lower
    "lower": "a-z",
    "digit": "0-9",
    "alnum": "a-z0-9",
    "xdigit": "0-9a-f",
    "space": r"\s",
    "blank": r" \t",
    "punct": r"!-/:-@\[-`{-~",
}
_NAMED = re.compile(r"\[:(\w+):\]")


def _close(path: str, at: int) -> int:
    """The index of the `]` that closes the bracket expression opened at `at`, or -1."""
    i = at + 1 + (path[at + 1 : at + 2] in ("!", "^"))
    i += path[i : i + 1] == "]"
    while i < len(path):
        named = _NAMED.match(path, i) if path.startswith("[:", i) else None
        if named:
            i = named.end()
        elif path[i] == "]":
            return i
        else:
            i += 1
    return -1


def _literal(piece: str) -> str:
    """Bracket text as regex class text; `[`, `&&`, `~~`, `||` and `--` would read as set operators (a FutureWarning)."""
    text = piece.replace("\\", "\\\\").replace("[", "\\[")
    return re.sub(r"-(?=-)", "-\\\\", re.sub(r"[&~|]", r"\\\g<0>", text))


def _bracket(body: str) -> str:
    """One bracket expression as a regex class; a class this does not know matches any character."""
    negated = body[:1] in ("!", "^")
    out = []
    for piece in re.split(r"(\[:\w+:\])", body[1:] if negated else body):
        named = _NAMED.fullmatch(piece)
        if named and named[1] not in _POSIX:
            return "[^/]"
        out.append(_POSIX[named[1]] if named else _literal(piece))
    return "[" + ("^" if negated else "") + "".join(out) + "]"


def _dot(cls: str) -> bool:
    """Whether a bracket class can match a dot; one that does not compile is read as able to."""
    try:
        return bool(re.fullmatch(cls, "."))
    except re.error:
        return True


def _squeeze(out: list[str]) -> list[str]:
    """Each run of `*` and `?` as its `?`s and one `*`: the same language, and no stars to backtrack over."""
    merged, run = [], []
    for token in [*out, ""]:
        if token in ("[^/]*", "[^/]"):
            run.append(token)
            continue
        merged += ["[^/]"] * run.count("[^/]") + ["[^/]*"] * ("[^/]*" in run)
        run = []
        merged.append(token)
    return merged


@cache
def pattern(path: str, *, loose: bool) -> re.Pattern[str]:
    """A glob (`*` `?` `[..]`, never matching `/` or a leading dot) and unknown variable text (anything) as a regex.

    A bracket expression that can match `.` (`[.]`, `[!a]`, `[[:punct:]]`) may match a leading dot.
    """
    out, at = ["(?:.*/)?" if loose else ""], 0
    while at < len(path):
        char = path[at]
        piece = PIECE.match(path, at) if char == "$" else None
        close = _close(path, at) if char == "[" else -1
        cls = _bracket(path[at + 1 : close]) if close > 0 else ""
        if char in "*?[" and (at == 0 or path[at - 1] == "/") and not (cls and _dot(cls)):
            out.append(r"(?!\.)")
        if piece:
            glued = (at > 0 and path[at - 1] != "/") or (piece.end() < len(path) and path[piece.end()] != "/")
            out.append("[^/]*" if glued else ".*")
            at = piece.end()
        elif close > 0:
            out.append(cls)
            at = close + 1
        else:
            out.append({"*": "[^/]*", "?": "[^/]"}.get(char) or re.escape(char))
            at += 1
    out = _squeeze(out)
    if out.count("[^/]*") > _STARS:  # stars between other characters backtrack: past a few, read as any text
        return re.compile(".*")
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

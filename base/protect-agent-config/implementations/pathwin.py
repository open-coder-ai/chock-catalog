"""Windows commands the shared parser does not know: move, xcopy, robocopy (stdlib only)."""

from __future__ import annotations

import posixpath
import re
from typing import Any

from pathwriters import dest

_WINOPT = re.compile(r"/[A-Za-z?]+(?:[:+-].*)?")
# robocopy options whose values are separate words: /XF files, /XD folders, /IF files
_LISTS = frozenset(("/xf", "/xd", "/if"))
_CURRENT = re.compile(r"%CD%", re.IGNORECASE)
_LOG = re.compile(r"/(?:uni)?log\+?:", re.IGNORECASE)


def _read(args: list[str]) -> tuple[list[str], set[str], list[str]]:
    """The words, the options (lowercase) and the path operands of a Windows copy command."""
    # `.cursor\ /e`: a trailing `\` escapes the space, so an option can sit inside the word before it (the `\` was a separator)
    split = [re.split(r"\s+(?=/)", a) for a in args]
    words = [_CURRENT.sub(".", p + "/" * (k < len(ps) - 1)) for ps in split for k, p in enumerate(ps)]
    flags: set[str] = set()
    ops, listed = [], False
    for word in words:
        if _WINOPT.fullmatch(word):
            flags.add(word.lower().split(":")[0])
            listed = word.lower() in _LISTS
        elif not (listed or word.startswith("-")):  # a word after /XD, /XF or /IF names what to skip, not a path
            ops.append(word.replace("\\", "/"))
    return words, flags, ops


def windows(w: Any, name: str, args: list[str], env: dict[str, str]) -> bool:
    """move is mv; xcopy and robocopy take `SOURCE DEST [files]`, and robocopy /MIR, /PURGE and /MOVE also delete."""
    words, flags, ops = _read(args)
    source, target, files = ops[0] if ops else "", ops[1] if len(ops) > 1 else "", ops[2:]
    gone = bool(flags & {"/move", "/mov"}) and w.reaches(
        source, env, parents=True, whole=True
    )  # /MOVE deletes the source
    if gone or any(w.reaches(a.split(":", 1)[1], env) for a in words if _LOG.match(a)):
        return True
    if name == "move":
        return dest(w, "mv", ops, env)
    if not target or w.reaches(target, env):
        return bool(target)
    holds = w.reaches(
        target, env, parents=True, whole=True
    )  # the repository folder, or one above it, holds every protected path
    if name == "robocopy":
        named = any(w.reaches(posixpath.join(target, f), env) for f in files)
        return holds and (not files or named or bool(flags & {"/mir", "/purge"}))
    if flags & {"/e", "/s", "/i", "/t"} or any(c in source for c in "*?") or source.endswith("/"):
        return holds
    return dest(w, "cp", [source, target], env) or (target.endswith("/") and holds)  # a folder: whatever it holds

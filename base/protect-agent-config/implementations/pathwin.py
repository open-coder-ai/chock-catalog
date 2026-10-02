"""Windows commands the shared parser does not know: move, xcopy, robocopy (stdlib only)."""

from __future__ import annotations

import posixpath
import re
from typing import Any

from pathwriters import dest

_WINOPT = re.compile(r"/[A-Za-z?]+(?:[:+].*)?")
_LOG = re.compile(r"/(?:uni)?log\+?:", re.IGNORECASE)


def windows(w: Any, name: str, args: list[str], env: dict[str, str]) -> bool:
    """move is mv; xcopy and robocopy take `SOURCE DEST [files]`, and robocopy /MIR, /PURGE and /MOVE also delete."""
    # `.cursor\ /e`: a trailing `\` escapes the space, so an option can sit inside the word before it
    args = [piece for a in args for piece in re.split(r"\s+(?=/)", a)]
    flags = {a.lower().split(":")[0] for a in args if _WINOPT.fullmatch(a)}
    ops = [a.replace("\\", "/") for a in args if not _WINOPT.fullmatch(a) and not a.startswith("-")]
    if any(w.reaches(a.split(":", 1)[1], env) for a in args if _LOG.match(a)):
        return True
    if name == "move":
        return dest(w, "mv", ops, env)
    source, target, files = ops[0] if ops else "", ops[1] if len(ops) > 1 else "", ops[2:]
    if not target or w.reaches(target, env):
        return bool(target)
    holds = w.reaches(target, env, parents=True)
    if flags & {"/move", "/mov"} and w.reaches(source, env, parents=True, whole=True):
        return True
    if name == "robocopy":
        named = any(w.reaches(posixpath.join(target, f), env) for f in files)
        return holds and (not files or named or bool(flags & {"/mir", "/purge"}))
    merged = flags & {"/e", "/s", "/i", "/t"} or "*" in source or source.endswith("/") or "?" in source
    return holds if merged else dest(w, "cp", [source, target], env)

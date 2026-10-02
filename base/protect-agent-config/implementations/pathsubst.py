"""What a substitution or a variable stands for when the line itself shows it (stdlib only)."""

from __future__ import annotations

import re
from collections.abc import Callable

_WORD = r"[\w./][\w./-]*"
_ECHO = re.compile(rf"echo\s+(?:'({_WORD})'|\"({_WORD})\"|({_WORD}))")
_GIT = re.compile(
    rf"git\s+rev-parse\s+(?:(--git-dir|--git-common-dir|--absolute-git-dir|--show-toplevel)|--git-path\s+({_WORD}))"
)
PWD = re.compile(r"\$(?:\{PWD\}|PWD(?!\w))")


def resolver(root: str) -> Callable[[str], str | None]:
    """The text a substitution body prints, when it is `echo WORD`, `pwd` or a `git rev-parse` of the repository paths.

    The repository folder is the one the guard runs in: git-dir is `.git` below it, as in a plain checkout.
    """
    known = re.fullmatch(r"[\w./-]+", root) is not None

    def read(body: str) -> str | None:
        body = body.strip()
        if body == "pwd":
            return "$PWD"
        if found := _ECHO.fullmatch(body):
            return next(g for g in found.groups() if g)
        found = _GIT.fullmatch(body)
        if not (found and known):
            return None
        if found[2]:
            return f"{root}/.git/{found[2]}"
        return root if found[1] == "--show-toplevel" else f"{root}/.git"

    return read


def rebound(name: str, text: str) -> bool:
    """Whether a variable is named in the line anywhere but as `$name`, `${name}` and its one assignment.

    That is the test for a `$(mktemp)` variable to stay fresh: `read x`, `for x in`, `printf -v x`, `x+=`, `declare x=`
    and every other way to set it name it as a word. A flag letter (`-f`) is not a mention.
    """
    reads = rf"\$\{{{name}\}}|\${name}(?!\w)"
    word = rf"(?:(?<![\w$./-])|(?<=-v)){name}(?!\w)"
    return len(re.findall(word, re.sub(reads, "", text))) != 1

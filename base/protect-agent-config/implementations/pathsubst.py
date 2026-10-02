"""What a substitution or a variable stands for when the line itself shows it (stdlib only)."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from typing import NamedTuple

from chock_shellparse.parse import _crude, _Scan

_WORD = r"[\w./][\w./-]*"
_ECHO = re.compile(rf"echo\s+(?:'({_WORD})'|\"({_WORD})\"|({_WORD}))")
_GIT = re.compile(
    rf"git\s+rev-parse\s+(?:(--git-dir|--git-common-dir|--absolute-git-dir|--show-toplevel)|--git-path\s+({_WORD}))"
)
_SHORT = 2
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


_ASSIGNED = re.compile(r"([A-Za-z_]\w*)(?:\[[^\]]*\])?\+?=")
_NAME = re.compile(r"([A-Za-z_]\w*)(?:\[.*\])?")
_EXPANSION = re.compile(r"\$\{(\w+):?=")
_LEAD = frozenset(("do", "then", "else", "elif", "if", "while", "until", "!", "command", "builtin", "time"))
_DECLARING = frozenset(("declare", "typeset", "local", "export", "readonly"))
_OPERATOR = re.compile(r"(?:[-+*/%&|^]|<<|>>)?=")
_STEP = re.compile(r"([A-Za-z_]\w*)(?:\+\+|--)")
_MANY = 2  # a count that is not 1: the variable is set more than by its one assignment
_DEPTH = 4


class Bindings(NamedTuple):
    """How often each variable is bound on a line, and the names bound through a reference."""

    counts: Counter[str]
    refs: frozenset[str]
    opaque: bool  # a script or computed text runs in this shell: it can set any variable

    def rebound(self, name: str) -> bool:
        """Whether a variable is set by anything but its one assignment, so a fresh `mktemp` value is no longer its value."""
        return self.opaque or name in self.refs or self.counts[name] != 1


class _Seen:
    """One pass over the clauses of a line: the constructs that bind a variable (stdlib only)."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.refs: set[str] = set()
        self.opaque = False

    def rebind(self, names: list[str]) -> None:
        for name in names:
            self.counts[name] += _MANY

    def clause(self, words: list[str], depth: int) -> None:
        for word in words:
            self.rebind(_EXPANSION.findall(word))  # `${x:=y}` sets x
        while words and words[0] in _LEAD:
            words.pop(0)
        while words and (found := _ASSIGNED.match(words[0])):  # `x=`, `x+=`, `x[0]=`, and a prefix `x=y cmd`
            self.counts[found[1]] += 1
            words.pop(0)
        if words:
            self.command(words[0], words[1:], depth)
            self.arithmetic(words)

    def arithmetic(self, words: list[str]) -> None:
        """`(( x = 1 ))`, `(( x += 1 ))` and `(( x++ ))` read as a command named x."""
        found = _STEP.fullmatch(words[0])
        if found or (len(words) > 1 and _OPERATOR.fullmatch(words[1])):
            self.rebind([found[1] if found else words[0]])

    def command(self, name: str, args: list[str], depth: int) -> None:
        plain = [a for a in args if not a.startswith("-")]
        if name in ("read", "mapfile", "readarray"):
            self.rebind([*_identifiers(plain), "REPLY" if name == "read" else "MAPFILE"])
        elif name in ("for", "select"):
            self.rebind(_identifiers(args[:1]))
        elif name == "printf":
            self.rebind(_identifiers(_printf(args)))
        elif name in _DECLARING:
            self.declare(args)
        elif name == "let":
            self.rebind(re.findall(r"[A-Za-z_]\w*", " ".join(args)))
        elif name in ("getopts", "unset"):
            self.rebind(_identifiers(plain[name == "getopts" :]))
        elif name == "eval":
            self.opaque |= any(c in a for a in args for c in "$`")  # computed text can set anything
            if depth >= _DEPTH:
                self.opaque = True  # nested too deep to read
                return
            inner = bindings(" ".join(args), depth + 1)
            self.counts.update(inner.counts)
            self.refs |= inner.refs
            self.opaque |= inner.opaque
        elif name in ("source", "."):
            self.opaque = True

    def declare(self, args: list[str]) -> None:
        """`declare x=`, `local x=`, `export x=` bind x; with -n x is a reference to another name, and that name is bound too."""
        reference = any(a.startswith("-") and not a.startswith("--") and "n" in a for a in args)
        for arg in args:
            name, equals, value = arg.partition("=")
            found = None if arg.startswith("-") else _NAME.fullmatch(name.removesuffix("+"))
            if found is None:
                continue
            self.counts[found[1]] += 1 if equals else 0
            if reference:
                self.refs.update((found[1], *_identifiers([value])))


def _identifiers(words: list[str]) -> list[str]:
    """The words that are a variable name (an element `a[0]` is its array)."""
    return [found[1] for word in words if (found := _NAME.fullmatch(word))]


def _printf(args: list[str]) -> list[str]:
    """The names `printf -v NAME` and `-vNAME` set."""
    names = []
    for at, arg in enumerate(args):
        if not arg.startswith("-"):
            break
        if arg == "-v" and at + 1 < len(args):
            names.append(args[at + 1])
        elif arg.startswith("-v") and len(arg) > _SHORT:
            names.append(arg[2:])
    return names


def bindings(text: str, depth: int = 0) -> Bindings:
    """Every binding of a variable in a line, found once: the test for a `$(mktemp)` variable to stay fresh."""
    seen = _Seen()
    for clause in _Scan(text).run() or _crude(text):
        seen.clause(list(clause.words), depth)
    return Bindings(seen.counts, frozenset(seen.refs), seen.opaque)

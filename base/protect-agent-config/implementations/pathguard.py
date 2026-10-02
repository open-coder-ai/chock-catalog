"""Judge a shell command by the paths it resolves to: working directory, `..`, variables, globs, whole directories (stdlib only)."""

from __future__ import annotations

import itertools
import os
import posixpath
import re
from collections.abc import Callable

from chock_shellparse import flags_of
from chock_shellparse.parse import _SHELLS, _WINPATH, Cmd, _parse, _Scan, is_powershell
from pathgit import git
from pathmatch import DYNAMIC, FRESH, expand, pattern, values
from pathscript import Scripts
from pathtext import braces, scan
from pathwin import windows
from pathwords import (
    CD,
    CHILDREN,
    DELETERS,
    DEST,
    GUARD_DIRS,
    POP,
    PUSH,
    REMOVERS,
    WINDOWS,
    ancestors,
    bound,
    is_interpreter,
    writes,
)
from pathwrap import WRAP, env_scripts, nested
from pathwriters import OUTPUT, awk, dest, find, output, sed

Normalise = Callable[[str], str]
_LEAD = re.compile(r"\$(?:\{(\w+)\}|(\w+))/(?=.)")
_ONLY = re.compile(r"\$(?:\{[^}]*\}|\w+)")
_DEPTH = 3


class _Walk(Scripts):
    """One command line, run in order against a virtual working directory."""

    def __init__(
        self,
        protected: tuple[str, ...],
        hit: Callable[[str], bool],
        normalise: Normalise,
        start: str,
        *,
        ps: bool,
    ) -> None:
        self.hit, self.normal, self.ps = hit, normalise, ps
        self.base = next((d for d in ancestors(start) if os.path.exists(os.path.join(d, ".git"))), start)
        self.root = self.normal(self.base)
        self.stack: list[str | None] = []
        self.docs: dict[str, str] = {}
        self.unsure: set[str] = set()
        self.prev: Cmd | None = None
        self.depth, self.blind, self.wrote = 0, False, False
        entries = [self.normal(entry).strip("/") for entry in (*protected, ".agents/policies/\0/implementations")]
        self.entries = entries
        self.files = [
            *entries,
            *(f"{e}{s}" for e in entries if e.endswith("/settings") for s in (".json", ".local.json")),
        ]
        self.dirs = sorted({"/".join(e.split("/")[:i]) for e in entries for i in range(1, e.count("/") + 1)})
        self.names = sorted({b for f in self.files if "." in (b := posixpath.basename(f))} | CHILDREN)
        parts = self.root.split("/")
        self.spots = [
            *("/".join(parts[:k]) or "/" for k in range(1, len(parts) + 1)),
            *(".", *("/".join([".."] * k) for k in range(1, len(parts)))),
            *("/".join([".."] * k + parts[-k:]) for k in range(1, len(parts))),
        ]
        self.here = [".", self.root]
        self.cwd = self._within(self.normal(start))
        self.handlers: dict[str, Callable[[Cmd], bool]] = {
            **dict.fromkeys(REMOVERS, self._remove),
            **dict.fromkeys(DEST - WINDOWS, lambda c: dest(self, c.name, c.args, c.env)),
            **dict.fromkeys(WINDOWS, lambda c: windows(self, c.name, c.args, c.env)),
            **dict.fromkeys(OUTPUT, lambda c: output(self, c.name, c.args, c.env)),
            **dict.fromkeys(("awk", "gawk", "mawk", "nawk"), lambda c: awk(self, c.args, c.env)),
            **dict.fromkeys(("sed", "yq"), lambda c: sed(self, c.args, c.env)),
            "git": lambda c: git(self, c.args, c.env),
            "find": lambda c: find(self, c.args, c.env),
            "dd": self._dd,
            "uniq": self._uniq,
        }

    def _within(self, path: str) -> str:
        if path == self.root:
            return "."
        return path[len(self.root) + 1 :] if path.startswith(self.root + "/") else path

    def _path(self, token: str, env: dict[str, str]) -> tuple[str, bool]:
        """The token as a repo-relative, normalised path, and whether the directory it is relative to is unknown."""
        word = expand(token, env).replace("\\", "/")
        if word == "~" or word.startswith("~/"):
            word = os.path.expanduser(word).replace("\\", "/")
        if word.startswith(
            FRESH
        ):  # a fresh path from mktemp: below it is safe, but `..` leaves it for somewhere unknown
            return (FRESH if ".." not in word.split("/") else "$__subst__"), False
        if word.startswith("$"):
            return self.normal(posixpath.normpath(word)), False
        if word.startswith("/"):
            return self._within(self.normal(posixpath.normpath(word))), False
        path = self.normal(posixpath.normpath(posixpath.join(self.cwd or "", word)))
        if path == ".." or path.startswith("../"):
            path = self._within(self.normal(posixpath.normpath(posixpath.join(self.root, path))))
        return path, self.cwd is None

    def _parent(self, path: str) -> bool:
        """Whether a path is a directory that holds a protected path."""
        parts = path.split("/")
        tails = ("/".join(parts[-k:]) for k in range(1, len(parts) + 1))
        return any(e == t or e.startswith(f"{t}/") for t in tails for e in self.entries) or bool(
            GUARD_DIRS.search(path)
        )

    def _holds(self, path: str, *, exact: bool = False) -> bool:
        """Whether a path is the repository folder (or, unless `exact`, one of its ancestors): they hold every protected path."""
        there = path if path.startswith("/") else self.normal(posixpath.normpath(posixpath.join(self.root, path)))
        return self.root == there or (not exact and self.root.startswith(there.rstrip("/") + "/"))

    def at_root(self, token: str, env: dict[str, str]) -> bool:
        """Whether a plain token names the repository folder itself."""
        path, _ = self._path(token, env)
        return not DYNAMIC.search(path) and self._holds(path, exact=True)

    def reaches(
        self, token: str, env: dict[str, str], *, parents: bool = False, whole: bool = False, root: bool = False
    ) -> bool:
        """Whether a token, read as a path (a glob, text with variables, a brace list), is protected or holds one.

        `parents` also counts a directory that holds a protected path; `whole` the repository folder and its ancestors,
        `root` the repository folder alone.
        """
        return any(
            self._reach(
                t, env, parents=parents, above=self.spots if whole else self.here if root else None, exact=not whole
            )
            for t in braces(token)
            if t
        )

    def _reach(self, token: str, env: dict[str, str], *, parents: bool, above: list[str] | None, exact: bool) -> bool:
        path, loose = self._path(token, env)
        if path == FRESH:
            return False
        if not (loose or DYNAMIC.search(path)):
            return (
                self.hit(path)
                or (parents and self._parent(path))
                or (above is not None and self._holds(path, exact=exact))
            )
        rx = pattern(path, loose=loose)
        if above is not None and any(map(rx.fullmatch, above)):
            return True
        files = (*self.files, *(self.names if loose else ()))
        everything = (*files, *(self.dirs if parents else ()))
        if (
            (lone := _LEAD.match(path))
            and not loose
            and (lone[1] or lone[2]) not in {n.lower() for n in (*env, "__subst__", *self.unsure)}
        ):
            # An unknown start can be the repository folder, so what follows it is a path from there.
            # ... which may be a folder on the way, so a name that can sit in a protected folder counts too.
            return self._below(path[lone.end() :], (*files, *self.names), (*everything, *self.names), ("",), loose=True)
        lead = ("", "/") if self.cwd in (None, ".") else ("", "/", f"{self.cwd}/")
        return self._below(path, files, everything, lead, loose=loose)

    @staticmethod
    def _below(
        path: str, files: tuple[str, ...], everything: tuple[str, ...], lead: tuple[str, ...], *, loose: bool
    ) -> bool:
        """Whether the path can be one of `everything`, or lies below one of `files` (a folder on the way to it)."""
        parts = path.split("/")
        way = ["/".join(parts[:k]) for k in range(1 + (len(parts) > 1 and bool(_ONLY.fullmatch(parts[0]))), len(parts))]
        return any(pattern(p, loose=loose).fullmatch(x + c) for p in way for c in files for x in lead) or any(
            pattern(path, loose=loose).fullmatch(x + c) for c in everything for x in lead
        )

    def under(self, start: str, env: dict[str, str]) -> list[str]:
        """The protected files and directories below a path, as written from the working directory."""
        path, loose = self._path(start, env)
        if self.hit(path):
            return [start]
        pool = [*self.files, *self.dirs]
        if loose or DYNAMIC.search(path) or self._holds(path):
            below = pool
        else:
            below = [p for p in pool if p.startswith(f"{path}/")]
        return [p if self.cwd in (None, ".") else posixpath.relpath(p, self.cwd) for p in below]

    def _chdir(self, cmd_name: str, args: list[str], env: dict[str, str]) -> None:
        if cmd_name in PUSH:
            self.stack.append(self.cwd)
        target = expand(next((a for a in args if a == "-" or not a.startswith("-")), ""), env) or "~"
        self.cwd = None if target == "-" or DYNAMIC.search(target) else self._path(target, env)[0]

    def _unknown(self, args: list[str], env: dict[str, str]) -> bool:
        """A command named by a variable or substitution: judged on the plain paths it is given and on what the line assigned."""
        plain = [a for a in values(args) if "/" in a or not DYNAMIC.search(expand(a, env))]
        return any(self.reaches(t, env, parents=True) for t in plain) or any(
            self.reaches(v, {}, parents=True) for v in env.values()
        )

    def _remove(self, cmd: Cmd) -> bool:
        flags = flags_of(cmd.args)
        recursive = bool(flags & {"-r", "-R"}) or any(a.lower().startswith("-rec") for a in cmd.args)
        whole = cmd.name in DELETERS or recursive
        return any(self.reaches(t, cmd.env, parents=True, whole=whole) for t in values(cmd.args))

    def _dd(self, cmd: Cmd) -> bool:
        return any(a.startswith("of=") and self.reaches(a[3:], cmd.env) for a in cmd.args)

    def _uniq(self, cmd: Cmd) -> bool:
        return any(self.reaches(t, cmd.env) for t in values(cmd.args)[1:2])

    def command(self, cmd: Cmd) -> bool:
        """Whether one simple command may write, delete, move or link a protected path."""
        name, args, env = cmd.name, cmd.args, cmd.env
        if any(self.reaches(t, env) for t in cmd.writes):
            return True
        if "$" in name:
            self.blind = True
            return self._unknown(args, env)
        if name in WRAP:
            return self.wrapped(cmd)
        handler = self.handlers.get(name) or (self.code if is_interpreter(name) else None)
        return handler is not None and handler(cmd)

    def step(self, cmd: Cmd, prev: Cmd | None, *, unparsed: bool) -> bool:
        if nested(cmd):  # a script the reader did not unwrap: it cannot be judged, so it is refused
            return True
        if cmd.name in CD:
            self._chdir(cmd.name, cmd.args, cmd.env)
        elif cmd.name in POP:
            self.cwd = self.stack.pop() if self.stack else None
        elif cmd.name in _SHELLS and ("-s" in cmd.args or not values(cmd.args)):
            return self.fed(cmd, prev)
        else:
            return self.command(cmd) or (unparsed and writes(cmd.name, cmd.writes))
        return False

    def run(self, text: str, *, ps: bool) -> bool:
        """Walk the commands of one script in order, tracking cd, pushd and popd."""
        unparsed, prev = _Scan(text).run() is None, None
        if any(self.loose(payload) for payload in env_scripts(text)):
            return True
        for cmd in _parse(text, {}, ps=ps, depth=0)[0]:
            self.prev = prev
            self.unsure.update(bound(cmd))
            if self.step(cmd, prev, unparsed=unparsed):
                return True
            self.wrote |= writes(cmd.name, cmd.writes)
            prev = cmd
        return False

    def _may_write(self, text: str) -> bool:
        """Whether a script holds a redirection or a command the guard judges by name."""
        cmds = _parse(text, {}, ps=self.ps, depth=0)[0]
        return any(writes(c.name, c.writes) or c.name in self.handlers or is_interpreter(c.name) for c in cmds)

    def script(self, text: str, depth: int) -> bool:
        """Whether a script, and each substitution in it, writes a protected path or may."""
        if depth > _DEPTH:
            return True
        self.depth, scanned = depth, scan(text)
        self.docs.update(scanned.docs)
        start, stack = self.cwd, list(self.stack)
        if self.run(scanned.outer, ps=self.ps):
            return True
        after = self.cwd, self.stack
        # A substitution runs wherever the line has got to: judge it from the start and from where the line ends.
        for body, (cwd, held) in itertools.product(scanned.bodies, ((start, stack), after)):
            self.cwd, self.stack = cwd, list(held)
            if depth < _DEPTH and self.script(body, depth + 1):
                return True
            if depth >= _DEPTH and self._may_write(body):
                return True  # too deep to judge: refused when it holds anything that could change a file
        self.cwd, self.stack = after
        self.depth = depth
        return False


def refuses(raw: str, protected: tuple[str, ...], hit: Callable[[str], bool], normalise: Normalise) -> bool:
    """Whether a command line writes, deletes, moves or links a protected path or a directory holding one, or may."""
    start = os.path.abspath(os.environ.get("CHOCK_HOOK_CWD") or os.getcwd())
    ps = is_powershell(raw)
    views = [raw.replace("\\", "/").replace("`", "")] if ps else list(dict.fromkeys([raw, _WINPATH.sub("/", raw)]))
    for view in views:
        walk = _Walk(protected, hit, normalise, start, ps=ps)
        if walk.script(view, 0) or (walk.blind and walk.wrote):
            return True
    return False

"""Resolve a path word against the virtual working directory and say whether it can reach a protected path (stdlib only)."""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Callable

from pathmatch import DYNAMIC, FRESH, expand, pattern
from pathtext import braces
from pathwords import GUARD_DIRS

_LEAD = re.compile(r"\$(?:\{(\w+)\}|(\w+))/(?=.)")
_ONLY = re.compile(r"\$(?:\{[^}]*\}|\w+)")


class Reach:
    """Methods of `_Walk` that read a path word and judge it against the protected entries."""

    hit: Callable[[str], bool]
    normal: Callable[[str], str]
    root: str
    cwd: str | None
    entries: list[str]
    files: list[str]
    dirs: list[str]
    names: list[str]
    kids: list[str]
    spots: list[str]
    here: list[str]
    unsure: set[str]

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
        if (lone := _LEAD.match(path)) and not loose:
            # An unknown start can be the repository folder, so what follows it is a path from there.
            # ... which may be a folder on the way, so a name that can sit in a protected folder counts too.
            return self._below(path[lone.end() :], (*files, *self.kids), (*everything, *self.kids), ("",), loose=True)
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

"""Follow the symlinks in a path to the files it really names (stdlib only)."""

from __future__ import annotations

import fnmatch
import os

from pathmatch import DYNAMIC, PIECE

_HOPS = 40  # the kernel's own limit on links followed for one path
# Folder entries a glob may read for one path: a wildcard over a larger tree is refused, never guessed at.
_BUDGET = 50000


class _SpentError(Exception):
    """More links or folder entries than the guard will follow."""


def _names(folder: str, head: str, spent: list[int]) -> list[str]:
    """The entries of a folder a path segment can stand for: a glob names each entry it matches, a plain name itself.

    A plain name is looked up as the filesystem does (a case-insensitive one finds a link under another case), never by a listing.
    """
    if not DYNAMIC.search(head):
        return [head]
    try:
        listing = os.listdir(folder)
    except OSError:
        listing = []
    spent[0] += len(listing)
    if spent[0] > _BUDGET:
        raise _SpentError
    glob = PIECE.sub("*", head).lower()
    return [n for n in listing if fnmatch.fnmatchcase(n.lower(), glob)]


def _target(full: str) -> str:
    """Where a link points, as an absolute path."""
    try:
        return os.path.normpath(os.path.join(os.path.dirname(full), os.readlink(full)))
    except OSError as exc:  # a link that cannot be read cannot be judged
        raise _SpentError from exc


def _go(folder: str, parts: list[str], spent: list[int], hops: int) -> set[str]:
    """Every absolute path `parts` can name below `folder`, links followed; `hops` counts the links on the way."""
    if not parts:
        return {folder}
    head, rest = parts[0], parts[1:]
    if head == "..":
        return _go(os.path.dirname(folder), rest, spent, hops)
    found: set[str] = set()
    for name in _names(folder, head, spent):
        full = os.path.join(folder, name)
        if not os.path.islink(full):
            found |= _go(full, rest, spent, hops)
        elif hops >= _HOPS:
            raise _SpentError
        else:
            for where in _go("/", [p for p in _target(full).split("/") if p], spent, hops + 1):
                found |= _go(where, rest, spent, hops + 1)
    return found


def follow(base: str, path: str) -> set[str] | None:
    """The absolute paths `path` (from `base`, or absolute) names once the links in it are followed.

    A glob names each entry it matches. None when the path is too wide, or a chain of links too long, to read: a caller must refuse.
    """
    try:
        return _go("/" if path.startswith("/") else base, [p for p in path.split("/") if p not in ("", ".")], [0], 0)
    except _SpentError:
        return None

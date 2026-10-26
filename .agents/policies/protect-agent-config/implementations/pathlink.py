"""Follow the symlinks in a path to the files it really names (stdlib only)."""

from __future__ import annotations

import fnmatch
import os
import re

from pathmatch import DYNAMIC, PIECE

_path = os.path  # the host's path rules; a test binds ntpath here to read Windows paths on any host
_HOPS = 40  # the kernel's own limit on links followed for one path
_SEGMENTS = 256  # `_go` recurses once per segment; a longer path is refused, never walked
# Folder entries a glob may read for one path: a wildcard over a larger tree is refused, never guessed at.
_BUDGET = 50000
_SEPARATORS = re.compile(r"[\\/]")
# Windows reports a resolved link as a device path: `\\?\C:\x` for a drive, `\\?\UNC\srv\share\x` for a share.
_DEVICE = re.compile(r"^[\\/]{2}[?.][\\/](UNC[\\/])?", re.IGNORECASE)
_WINDOWS = re.compile(r"^(?:[a-z]:/|//)", re.IGNORECASE)  # a drive or share path, separators already read as slashes


class _SpentError(Exception):
    """More links or folder entries than the guard will follow."""


def _plain(path: str) -> str:
    """The path without a Windows device prefix: `\\\\?\\C:\\x` is `C:\\x`, `\\\\?\\UNC\\srv\\share\\x` is `\\\\srv\\share\\x`."""
    return _DEVICE.sub(lambda found: "//" if found[1] else "", path)


def _split(path: str) -> tuple[str, list[str]]:
    """Where a path starts (its root, or `` when it is relative) and its segments, both separators read and `.` dropped."""
    drive, rest = _path.splitdrive(_plain(path))
    parts = [p for p in _SEPARATORS.split(rest) if p not in ("", ".")]
    return (drive + _path.sep if _SEPARATORS.match(rest) else ""), parts


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
        return _path.normpath(_path.join(_path.dirname(full), _plain(os.readlink(full))))
    except OSError as exc:  # a link that cannot be read cannot be judged
        raise _SpentError from exc


def _go(folder: str, parts: list[str], spent: list[int], hops: int) -> set[str]:
    """Every absolute path `parts` can name below `folder`, links followed; `hops` counts the links on the way."""
    if not parts:
        return {folder}
    head, rest = parts[0], parts[1:]
    if head == "..":
        return _go(_path.dirname(folder), rest, spent, hops)
    found: set[str] = set()
    for name in _names(folder, head, spent):
        full = _path.join(folder, name)
        if not _path.islink(full):
            found |= _go(full, rest, spent, hops)
        elif hops >= _HOPS:
            raise _SpentError
        else:
            root, below = _split(_target(full))
            for where in _go(root or _path.dirname(full), below, spent, hops + 1):
                found |= _go(where, rest, spent, hops + 1)
    return found


def follow(base: str, path: str) -> set[str] | None:
    """The absolute paths `path` (from `base`, or absolute) names once the links in it are followed.

    A glob names each entry it matches. None when the path is too wide, or a chain of links too long, to read: a caller must refuse.
    """
    try:
        root, parts = _split(path)
        if len(parts) > _SEGMENTS:
            return None
        return _go(root or base, parts, [0], 0)
    except (_SpentError, RecursionError):  # a chain of links can nest deeper than its first path does
        return None


def within(real: str, there: str) -> str:
    """`there` from the repository folder `real` when it lies inside it (`.` for the folder itself), else as it is.

    Separators are read as slashes; a drive or share path is compared in any case, as Windows does.
    """
    top, path = real.replace("\\", "/").rstrip("/"), there.replace("\\", "/")
    top_key, path_key = (top.lower(), path.lower()) if _WINDOWS.match(top) else (top, path)
    if path_key == top_key:
        return "."
    return path[len(top) + 1 :] if path_key.startswith(top_key + "/") else path

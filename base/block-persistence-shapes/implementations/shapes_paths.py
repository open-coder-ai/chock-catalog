"""Paths that keep a program running after the session, read with ~ and $HOME as the home folder."""

import posixpath
import re
from collections.abc import Callable
from functools import cache

from chock_shellparse import Cmd

HOME = re.compile(r"^(?:~[^/]*|\$\{?home\}?|\$env:(?:userprofile|home))(?=/|$)", re.IGNORECASE)
SPLIT = re.compile(r"""[\s'",()=;]+""")
CD = frozenset(("cd", "pushd", "chdir", "set-location", "sl"))
ANCHORED = ("/", "~", "$")


def norm(path: str) -> str:
    """Lowercase, home written `~`, `.` and `..` folded: `$HOME/.ssh/../.ssh/Authorized_Keys` is one path."""
    return posixpath.normpath(HOME.sub("~", re.sub("^/{2,}", "/", path.replace("\\", "/"))).lower())


@cache
def compiled(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern) for pattern in patterns)


def named(path: str, patterns: tuple[str, ...]) -> bool:
    """Whether the path, or a word inside it (code passed to an interpreter), matches one of the patterns."""
    pieces = {norm(piece) for piece in (path, *SPLIT.split(path)) if piece}
    return any(rx.search(piece) for piece in pieces for rx in compiled(patterns))


def enters(cmd: Cmd, tab: dict, *, hot: bool) -> bool:
    """Whether the working directory is a folder of persistence files after this command."""
    if cmd.name not in CD or not cmd.args:
        return hot
    target = norm(cmd.args[-1])
    return named(target, tuple(tab["dir_paths"])) or (hot and not target.startswith(ANCHORED))


def hits(tab: dict, *, hot: bool) -> Callable[[str], bool]:
    """The test `writes_files` applies to each path: a persistence file or folder, or any relative path in one."""
    patterns = (*tab["file_paths"], *tab["dir_paths"])

    def hit(path: str) -> bool:
        return named(path, patterns) or (hot and bool(path) and not norm(path).startswith(ANCHORED))

    return hit

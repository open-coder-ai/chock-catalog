"""The command names, and the names inside protected folders, that the path guard reasons about (stdlib only)."""

from __future__ import annotations

import ntpath
import os
import re
from collections.abc import Iterator

from chock_shellparse.parse import Cmd
from pathmatch import DRIVE

CD = frozenset(("cd", "chdir", "pushd", "set-location", "sl", "push-location"))
PUSH = frozenset(("pushd", "push-location"))
POP = frozenset(("popd", "pop-location"))
DELETERS = frozenset(("rm", "rmdir", "unlink", "shred", "remove-item", "ri", "del", "erase", "rd"))
# Writers the guard names beyond the shared parser's remover list (a test pins the rest to it): editors, and tools it lacks.
EXTRA_REMOVERS = frozenset(
    ("vi", "vim", "nvim", "nano", "emacs", "sponge", "chattr", "rename", "attrib", "icacls", "takeown")
)
REMOVERS = frozenset(
    (
        *("tee", "chmod", "chown", "truncate", "patch", "ed", "ex", "touch", *DELETERS),
        *("set-content", "add-content", "out-file", "new-item", "clear-content", "move-item", "set-item"),
        *("rename-item", "tee-object", "sc", "ac", "ni", "mi", "rni", "ren", *EXTRA_REMOVERS),
    )
)
# Windows commands the shared parser does not know: move, xcopy and robocopy write a destination (pathwriters.windows).
WINDOWS = frozenset(("move", "xcopy", "robocopy", "mklink"))
DEST = frozenset(("cp", "install", "ln", "mv", "rsync", "scp", "copy-item", "copy", "cpi", *WINDOWS))
INTERPRETERS = ("python", "pypy", "perl", "ruby", "node", "php")
CODERS = ("lua", "luajit", "deno", "bun", "rscript", "julia", "groovy", "osascript", "tclsh")
# Names that can sit in a protected directory whose other contents are unknown: the engine launcher, git hooks, hook files.
CHILDREN = frozenset(
    (
        *("chock", "chock.cmd", "chock.exe", "chock.json", "agentseam.json", "hooks.json"),
        *("pre-commit", "commit-msg", "pre-push", "pre-merge-commit", "prepare-commit-msg", "post-commit"),
        *("post-checkout", "post-merge", "post-rewrite", "pre-rebase", "pre-auto-gc", "update", "applypatch-msg"),
        *("pre-applypatch", "post-update", "push-to-checkout", "reference-transaction", "fsmonitor-watchman"),
        *("post-applypatch", "pre-receive", "proc-receive", "post-receive", "sendemail-validate", "post-index-change"),
        *("p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit"),
    )
)
PRODUCERS = frozenset(("echo", "printf", "cat"))
GUARD_DIRS = re.compile(r"(?:^|/)\.agents(?:/policies(?:/[^/]+)?)?$")


def ancestors(path: str) -> Iterator[str]:
    """The path and each folder above it; a drive-letter path is read as Windows reads it, on any system."""
    split = ntpath.dirname if DRIVE.match(path) else os.path.dirname
    while True:
        yield path
        parent = split(path)
        if parent == path:
            return
        path = parent


def is_interpreter(name: str) -> bool:
    """A language runtime that takes code on its command line."""
    return name.startswith(INTERPRETERS) or name in CODERS


def writes(name: str, redirects: list[str]) -> bool:
    return bool(redirects) or name in REMOVERS | DEST | {"dd"}


def bound(cmd: Cmd) -> list[str]:
    """Names a command sets from input the line does not show: `read X`, `for X in ..`, `printf -v X`."""
    if cmd.name in ("read", "mapfile", "readarray"):
        return [a for a in cmd.args if not a.startswith("-")]
    if cmd.name in ("for", "select"):
        return cmd.args[:1]
    return [cmd.args[cmd.args.index("-v") + 1]] if cmd.name == "printf" and "-v" in cmd.args[:-1] else []

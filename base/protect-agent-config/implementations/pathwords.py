"""The command names, and the names inside protected folders, that the path guard reasons about (stdlib only)."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator

from chock_shellparse.parse import Cmd

CD = frozenset(("cd", "chdir", "pushd", "set-location", "sl", "push-location"))
PUSH = frozenset(("pushd", "push-location"))
POP = frozenset(("popd", "pop-location"))
DELETERS = frozenset(("rm", "rmdir", "unlink", "shred", "remove-item", "ri", "del", "erase", "rd"))
REMOVERS = frozenset(
    (
        *(
            "tee",
            "chmod",
            "chown",
            "truncate",
            "patch",
            "ed",
            "ex",
            "vi",
            "vim",
            "nvim",
            "nano",
            "emacs",
            "touch",
            "sponge",
            "chattr",
            *DELETERS,
        ),
        *("set-content", "add-content", "out-file", "new-item", "clear-content", "move-item", "set-item"),
        *("rename-item", "tee-object", "sc", "ac", "ni", "mi", "rni", "ren"),
    )
)
DEST = frozenset(("cp", "install", "ln", "mv", "rsync", "scp", "copy-item", "copy", "cpi"))
INTERPRETERS = ("python", "perl", "ruby", "node", "php")
# Names that can sit in a protected directory whose other contents are unknown: the engine launcher, git hooks, hook files.
CHILDREN = frozenset(
    (
        *("chock", "chock.cmd", "chock.exe", "chock.json", "agentseam.json", "hooks.json"),
        *("pre-commit", "commit-msg", "pre-push", "pre-merge-commit", "prepare-commit-msg", "post-commit"),
        *("post-checkout", "post-merge", "post-rewrite", "pre-rebase", "pre-auto-gc", "update", "applypatch-msg"),
        *("pre-applypatch", "post-update", "push-to-checkout", "reference-transaction", "fsmonitor-watchman"),
    )
)
PRODUCERS = frozenset(("echo", "printf", "cat"))
GUARD_DIRS = re.compile(r"(?:^|/)\.agents(?:/policies(?:/[^/]+)?)?$")


def ancestors(path: str) -> Iterator[str]:
    while True:
        yield path
        parent = os.path.dirname(path)
        if parent == path:
            return
        path = parent


def writes(name: str, redirects: list[str]) -> bool:
    return bool(redirects) or name in REMOVERS | DEST | {"dd"}


def bound(cmd: Cmd) -> list[str]:
    """Names a command sets from input the line does not show: `read X`, `for X in ..`, `printf -v X`."""
    if cmd.name in ("read", "mapfile", "readarray"):
        return [a for a in cmd.args if not a.startswith("-")]
    if cmd.name in ("for", "select"):
        return cmd.args[:1]
    return [cmd.args[cmd.args.index("-v") + 1]] if cmd.name == "printf" and "-v" in cmd.args[:-1] else []

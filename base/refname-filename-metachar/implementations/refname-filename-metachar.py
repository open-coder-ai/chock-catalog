#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse a shell command that creates a branch, tag or file whose name a shell, a CI step or git can misread.
# Refs: git branch|tag|checkout -b|switch -c|worktree add -b|push <dst>|fetch <src>:<dst>|update-ref. Files: redirect
# targets and the operands of touch, mkdir, tee, cp, mv, install, ln, rsync, git mv, dd of=, PowerShell -Path/-Name.
# Substitution syntax counts only when the command spells it literally (single quotes or a backslash): unquoted, the
# shell expands it and the name is whatever it expands to, which the commit gate and the pre-push hook then judge.

import os
import re
import shlex
import sys
from itertools import pairwise

from chock_shellparse import Cmd, commands, git_parts
from refname_git import created_refs
from refname_rules import SUBST, describe, problems, ref_problems

CREATORS = frozenset(
    ("touch", "mkdir", "tee", "cp", "mv", "install", "ln", "rsync", "scp", "copy", "move", "md", "ren", "rename")
)
PS_CREATORS = frozenset(
    ("new-item", "ni", "copy-item", "cpi", "move-item", "mi", "rename-item", "rni", "set-content", "out-file")
)
PS_PATH_FLAGS = frozenset(("-path", "-literalpath", "-name", "-newname", "-destination", "-filepath"))
# Substitution syntax inside single quotes, or a backslash-escaped `$` or backtick: the name keeps it literally.
LITERAL = re.compile(r"'[^']*(?:\$[({'\"]|\$IFS|`)[^']*'|\\[$`]")


def _ps_paths(args: list[str]) -> list[str]:
    """A cmdlet's -Path/-Name/-Destination values, spaced (`-Path x`) or glued (`-Path:x`)."""
    found = [value for flag, value in pairwise(args) if flag.lower() in PS_PATH_FLAGS]
    glued = (arg.split(":", 1) for arg in args if ":" in arg)
    return found + [value for flag, value in glued if flag.lower() in PS_PATH_FLAGS]


def file_operands(cmd: Cmd) -> list[str]:
    """Paths a command may create: redirect targets, a creator's operands, dd's of=, a cmdlet's -Path or -Name."""
    found = list(cmd.writes)
    if cmd.name in CREATORS:
        dashes = True
        for arg in cmd.args:
            if dashes and arg == "--":
                dashes = False
            elif not (dashes and arg.startswith("-")):
                found.append(arg)
    elif cmd.name == "dd":
        found += [arg[3:] for arg in cmd.args if arg.startswith("of=")]
    elif cmd.name in PS_CREATORS:
        found += _ps_paths(cmd.args)
    elif cmd.name == "git":
        sub, _, rest = git_parts(cmd.args)
        if sub == "mv":
            found += [arg for arg in rest if not arg.startswith("-")]
    return found


def named(cmd: Cmd) -> list[tuple[str, str, list[tuple[str, str]]]]:
    """(kind, name, problems) for every ref and path the command would create."""
    found = []
    if cmd.name == "git":
        sub, _, rest = git_parts(cmd.args)
        found += [("branch or tag name", ref, ref_problems(ref)) for ref in created_refs(sub, rest, cmd.doc)]
    found += [("file name", path, problems(path, dotdot=False)) for path in file_operands(cmd)]
    return found


def check(raw: str) -> str | None:
    """The reason the command creates a misreadable name, or None."""
    literal = bool(LITERAL.search(raw))
    for cmd in commands(raw):
        for kind, name, found in named(cmd):
            kept = [item for item in found if literal or item[0] != SUBST]
            if kept:
                return describe(kind, name, kept)
    return None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"refname-filename-metachar: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

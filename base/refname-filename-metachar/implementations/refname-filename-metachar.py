#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse a shell command that creates a branch, tag or file whose name a shell, a CI step or git can misread.
# Refs: see refname_git.py. Files: redirect targets, every operand of touch, mkdir and tee, the destination of cp,
# mv, install, ln, rsync, scp and git mv (a source keeps its name, so renaming a bad file away passes), dd of=,
# git worktree add's path, and a cmdlet's -Path/-Name/-NewName/-Destination (abbreviated or positional).
# What the shell expands is marked first (refname_shell.py), so `"${OUT}/x"` is not substitution syntax and
# `a$\(id\)` or `$'a\x3bb'` is judged as the name bash would create.

import os
import shlex
import sys

from chock_shellparse import Cmd, commands, git_parts, is_powershell
from refname_git import WORKTREE, created_refs, parse
from refname_rules import describe, problems, ref_problems
from refname_shell import EXPANDED, mark_expansions

EVERY_OPERAND = frozenset(("touch", "mkdir", "tee", "md"))
DESTINATION = frozenset(("cp", "mv", "install", "ln", "rsync", "scp", "copy", "move", "ren", "rename"))
TARGET_FLAGS = ("-t", "--target-directory")
PS_FLAGS = ("-path", "-literalpath", "-name", "-newname", "-destination", "-filepath")
PS_VALUE_FLAGS = frozenset((*PS_FLAGS, "-value", "-itemtype", "-type", "-encoding", "-filter", "-include", "-exclude"))
# Which positional argument a cmdlet takes as the path it creates: the first, or the second (-NewName, -Destination).
PS_POSITION = {
    **dict.fromkeys(("new-item", "ni", "set-content", "sc", "out-file", "add-content", "ac"), 0),
    **dict.fromkeys(("copy-item", "cpi", "move-item", "mi", "rename-item", "rni"), 1),
}


def _ps_flag(arg: str, choices: frozenset[str] | tuple[str, ...]) -> str:
    """A cmdlet parameter, unabbreviated: PowerShell accepts any unambiguous prefix."""
    low = arg.lower()
    matches = [full for full in choices if full.startswith(low)] if low.startswith("-") and len(low) > 1 else []
    return low if low in choices else (matches[0] if len(matches) == 1 else "")


def _ps_paths(args: list[str], position: int) -> list[str]:
    """A cmdlet's path values, spaced (`-Path x`), glued (`-Path:x`) or positional."""
    found, positional, items = [], [], iter(args)
    for arg in items:
        flag, colon, glued = arg.partition(":")
        name = _ps_flag(flag, PS_VALUE_FLAGS)
        if name and colon:
            found += [glued] if name in PS_FLAGS else []
        elif name:
            value = next(items, "")
            found += [value] if name in PS_FLAGS else []
        elif not arg.startswith("-"):
            positional.append(arg)
    return found + positional[position : position + 1]


def _operands(args: list[str]) -> list[str]:
    """Arguments that are not options; after `--` every argument is one."""
    found, options = [], True
    for arg in args:
        if options and arg == "--":
            options = False
        elif not (options and arg.startswith("-")):
            found.append(arg)
    return found


def _destination(args: list[str]) -> list[str]:
    """The path cp, mv and the like create: a -t/--target-directory value, else the last operand."""
    for at, arg in enumerate(args):
        if arg in TARGET_FLAGS:
            return args[at + 1 : at + 2]
        if arg.startswith("--target-directory="):
            return [arg.split("=", 1)[1]]
    return _operands(args)[-1:]


def file_operands(cmd: Cmd) -> list[str]:
    """Paths a command may create under a name it chooses."""
    found = list(cmd.writes)
    if cmd.name in EVERY_OPERAND:
        found += _operands(cmd.args)
    elif cmd.name in DESTINATION:
        found += _destination(cmd.args)
    elif cmd.name == "dd":
        found += [arg[3:] for arg in cmd.args if arg.startswith("of=")]
    elif cmd.name in PS_POSITION:
        found += _ps_paths(cmd.args, PS_POSITION[cmd.name])
    elif cmd.name == "git":
        sub, _, rest = git_parts(cmd.args)
        if sub == "mv":
            found += _destination(rest)
        elif sub == "worktree" and rest[:1] == ["add"]:
            found += parse(rest[1:], WORKTREE)[1][:1]
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
    for cmd in commands(mark_expansions(raw, powershell=is_powershell(raw))):
        for kind, name, found in named(cmd):
            if found:
                return describe(kind, name.replace(EXPANDED, "$"), found)
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

#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse a shell command that creates a branch, tag or file whose name a shell, a CI step or git can misread.
# Refs: see refname_git.py. Files: redirect targets, every operand of touch, mkdir and tee, the destination of cp,
# mv, install, ln, rsync, scp and git mv (a source keeps its name, so renaming a bad file away passes), dd of=,
# git worktree add's path, and a cmdlet's -Path/-Name/-NewName/-Destination (abbreviated or positional).
# What the shell expands is marked first (refname_shell.py), so `"${OUT}/x"` is not substitution syntax and
# `a$\(id\)` or `$'a\x3bb'` is judged as the name bash would create. Every inner script -- a command substitution,
# a backtick command, a process substitution, a `bash -c` or `eval` script -- is marked and judged the same way.

import os
import shlex
import sys

import chock_shellparse.parse as shellparse
from chock_shellparse import Cmd, commands, git_parts, is_powershell
from refname_git import WORKTREE, created_refs, parse
from refname_rules import describe, problems, ref_problems
from refname_shell import EXPANDED, TooDeepError, UnreadableError, mark_expansions

EVERY_OPERAND = frozenset(("touch", "mkdir", "tee", "md"))
DESTINATION = frozenset(("cp", "mv", "install", "ln", "rsync", "scp", "copy", "move", "ren", "rename"))
TARGET_FLAGS = ("-t", "--target-directory")
PS_FLAGS = ("-path", "-literalpath", "-name", "-newname", "-destination", "-filepath")
PS_VALUE_FLAGS = frozenset((*PS_FLAGS, "-value", "-itemtype", "-type", "-encoding", "-filter", "-include", "-exclude"))
# Bounds on what one command line may hold; past any of them the line is refused, never passed unread.
MAX_DEPTH, MAX_SCRIPTS, MAX_TEXT, MAX_PARSED, LONG_UNBALANCED = 8, 512, 1_000_000, 1_000_000, 4096
TOO_DEEP = "command line holds more nested script than this guard judges, so a name in it cannot be checked."
UNCLOSED = "command line opens a substitution it never closes, so a name after it cannot be checked."
UNBALANCED = "command line is long and its quoting does not balance, so a name in it cannot be checked in time."
_SCRIPTS: list[str] = []  # bash -c and eval scripts met while parsing, judged after the line that holds them
_PARSE = shellparse._parse
_PARSED = [0]  # characters chock_shellparse has read for this command line, bounded by MAX_PARSED


def _parse_marked(text: str, env: dict[str, str], *, ps: bool, depth: int) -> tuple[list[Cmd], dict[str, str]]:
    """chock_shellparse's reader, with each bash -c or eval script's expansions marked before it is read."""
    _PARSED[0] += len(text)
    if _PARSED[0] > MAX_PARSED:
        raise TooDeepError
    if depth:
        text, inner = mark_expansions(text, powershell=ps)
        _SCRIPTS.extend(inner)
    return _PARSE(text, env, ps=ps, depth=depth)


shellparse._parse = _parse_marked
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


def _scripts(cmds: list[Cmd], inner: list[str]) -> list[str]:
    """The scripts a line holds: substitutions, bash -c and eval scripts, and any left unread at the parser's depth."""
    leftover = [script for cmd in cmds if (script := shellparse._inner(cmd.name, cmd.args)) is not None]
    return list(dict.fromkeys([*inner, *_SCRIPTS, *leftover]))


def check(raw: str) -> str | None:
    """The reason the command creates a misreadable name, or None."""
    pending, seen, budget = [(raw, 0)], set(), MAX_TEXT
    _PARSED[0] = 0
    while pending:
        script, depth = pending.pop(0)
        if script in seen:
            continue
        seen.add(script)
        budget -= len(script)
        if depth > MAX_DEPTH or len(seen) > MAX_SCRIPTS or budget < 0:
            return TOO_DEEP
        try:
            text, inner = mark_expansions(script, powershell=is_powershell(script))
            if len(text) > LONG_UNBALANCED and shellparse._Scan(text).run() is None:
                return UNBALANCED  # the parser's fallback for unbalanced quoting slows quadratically
            _SCRIPTS.clear()
            cmds = commands(text)
        except TooDeepError:
            return TOO_DEEP
        except UnreadableError:
            return UNCLOSED
        pending += [(inner_script, depth + 1) for inner_script in _scripts(cmds, inner)]
        found = [item for cmd in cmds for item in named(cmd) if item[2]]
        if found:
            kind, name, problems_found = found[0]
            return describe(kind, name.replace(EXPANDED, "$"), problems_found)
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

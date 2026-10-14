#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse shell commands that write to agent-config or vendored enforcement paths, or run `chock resume`; reads and `chock sync` pass.
# Best effort: a write must target a protected path or a directory holding one, as the command resolves it (cd, `..`, variables, globs; see pathguard.py).

import os
import re
import shlex
import sys

from chock_shellparse import commands, writes_files
from pathguard import refuses
from pathload import loads_plugin
from pathopaque import refuses as opaque
from pathset import ASK as ASKED
from pathset import BLOCK, PROTECTED, hit, normalise, verdict
from pathwrap import too_deep

# `hit` and `normalise` are the guard's path test, which the tests and the gate's parity check call as `guard.hit`.
__all__ = ["ASK", "BLIND", "DEEP", "LOADS", "PROTECTED", "REASON", "RESUMES", "check", "hit", "normalise", "run"]

REASON = "shell write touching agent config is refused -- an agent must not edit its own guardrails. Regenerate managed files with `chock sync`. For any other change, ask the person: they make it from their own shell."

# A lone `\` ends the line: for a Windows command (copy, xcopy, move) it closes a folder name, it escapes nothing.
_TRAILING = re.compile(r"(?<=[^\s\\])\\$")

LOADS = "shell command makes Claude Code load a plugin from a folder (CLAUDE_CODE_PLUGIN_DIRS, `claude --plugin-dir`) -- refused: a plugin's hooks run above the project's own gates. Ask the person, who sets it from their own shell."

BLIND = "shell command runs script text the guard cannot read (eval or a shell fed from a variable, a pipe or a here-document, a variable as the command, trap, xargs sh, an interpreter one-liner) and names a protected path -- refused because it cannot be judged. Run the inner command directly, or ask the person."

ASK = "shell write to an instruction file under docs/ needs a person's decision -- it is documentation about a guardrail file, but the same name is read as instructions where it sits. Ask the person, or make the change from their own shell."

RESUMES = "shell command runs `chock resume` -- refused: only a person lifts a stop (`chock stop`), from their own terminal. Ask the person."

# `chock resume` as its launcher spells it: the engine's own name, or Python running its module.
_CHOCK = frozenset(("chock", "chock.exe", "chock.cmd"))

DEEP = "shell command nested too deep to check (a script inside a script, five or more levels) -- refused because it cannot be judged. Run the inner commands one at a time, or ask the person."


# Python's short options: flags that take no value, and the ones whose value follows (`-X dev`, `-W error`).
_PY_FLAGS = "bBdEhiIOPqRsSuvx"
_PY_MODULE = re.compile(rf"-[{_PY_FLAGS}]*m(.*)")
_PY_VALUED = re.compile(rf"-[{_PY_FLAGS}]*[XW]$")
_PY_CODE = re.compile(rf"-[{_PY_FLAGS}]*c")
# `script` (util-linux) runs the command its `-c` (in a cluster: `-qec`) or `--command` names; BSD's runs the words after its file.
_SCRIPT_C = re.compile(r"-[a-zA-Z]*c(.*)")
_DEPTH = 4


def _python_module(args: list[str]) -> tuple[str, list[str]] | None:
    """The module `python [options] -m <module> args` runs and its arguments (`-mchock`, `-Im chock`, `-X v -m chock`), or None."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-":
        found = _PY_MODULE.fullmatch(args[i])
        if found:
            if found.group(1):
                return found.group(1), args[i + 1 :]
            return (args[i + 1 : i + 2] or [""])[0], args[i + 2 :]
        if _PY_CODE.match(args[i]):
            return None
        i += 2 if _PY_VALUED.match(args[i]) else 1
    return None


def _script_command(args: list[str]) -> str | None:
    """The command line `script` runs: `-c CMD`, `-qec CMD`, `-cCMD`, `--command[=]CMD`, or BSD's `script [-q] file cmd args`."""
    for i, arg in enumerate(args):
        if arg.startswith("--command"):
            return arg.split("=", 1)[1] if "=" in arg else " ".join(args[i + 1 : i + 2])
        found = _SCRIPT_C.fullmatch(arg) if not arg.startswith("--") else None
        if found:
            return found.group(1) or " ".join(args[i + 1 : i + 2])
    words = [a for a in args if not a.startswith("-")]
    return " ".join(words[1:]) or None


def _resumes(name: str, args: list[str], depth: int = 0) -> bool:
    """Whether a command is `chock resume`, `python -m chock resume`, or `script` running one, whatever options come first."""
    if name.startswith(("python", "py")):
        module = _python_module(args)
        if module is None or module[0].split(".")[0] != "chock":
            return False
        name, args = "chock", module[1]
    if name == "script":
        inner = _script_command(args)
        return (
            inner is not None and depth < _DEPTH and any(_resumes(c.name, c.args, depth + 1) for c in commands(inner))
        )
    words = [a for a in args if not a.startswith("-")]
    return name in _CHOCK and words[:1] == ["resume"]


def check(raw: str) -> str | None:
    """The reason a command edits protected files (REASON, LOADS, BLIND, DEEP) or lifts a stop (RESUMES), ASK when it only writes docs instruction files, or None."""
    raw = _TRAILING.sub("/", raw.rstrip())
    if too_deep(raw):
        return DEEP
    if any(_resumes(cmd.name, cmd.args) for cmd in commands(raw)):
        return RESUMES
    asked: list[str] = []

    def firm(path: str) -> bool:
        kind = verdict(path)
        if kind == ASKED:
            asked.append(path)
        return kind == BLOCK

    if any(writes_files(cmd, firm) for cmd in commands(raw)) or refuses(raw, PROTECTED, firm, normalise):
        return REASON
    if loads_plugin(raw):
        return LOADS
    if opaque(raw, firm):
        return BLIND
    return ASK if asked else None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"protect-agent-config: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"{'ASK' if reason == ASK else 'BLOCKED'}: {reason}", file=sys.stderr)
        return 3 if reason == ASK else 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

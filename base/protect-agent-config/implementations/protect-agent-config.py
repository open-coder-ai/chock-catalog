#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse shell commands that write to agent-config or vendored enforcement paths; reads and `chock sync` pass.
# Best effort: a write must target a protected path or a directory holding one, as the command resolves it (cd, `..`, variables, globs; see pathguard.py).

import os
import re
import shlex
import sys

from chock_shellparse import commands, writes_files
from pathguard import refuses
from pathopaque import refuses as opaque
from pathset import ASK as ASKED
from pathset import BLOCK, PROTECTED, hit, normalise, verdict
from pathwrap import too_deep

# `hit` and `normalise` are the guard's path test, which the tests and the gate's parity check call as `guard.hit`.
__all__ = ["ASK", "BLIND", "DEEP", "PROTECTED", "REASON", "check", "hit", "normalise", "run"]

REASON = "shell write touching agent config is refused -- an agent must not edit its own guardrails. Regenerate managed files with `chock sync`. For any other change, ask the person: they make it from their own shell."

# A lone `\` ends the line: for a Windows command (copy, xcopy, move) it closes a folder name, it escapes nothing.
_TRAILING = re.compile(r"(?<=[^\s\\])\\$")

BLIND = "shell command runs script text the guard cannot read (eval or a shell fed from a variable, a pipe or a here-document, a variable as the command, trap, xargs sh, an interpreter one-liner) and names a protected path -- refused because it cannot be judged. Run the inner command directly, or ask the person."

ASK = "shell write to an instruction file under docs/ needs a person's decision -- it is documentation about a guardrail file, but the same name is read as instructions where it sits. Ask the person, or make the change from their own shell."

DEEP = "shell command nested too deep to check (a script inside a script, five or more levels) -- refused because it cannot be judged. Run the inner commands one at a time, or ask the person."


def check(raw: str) -> str | None:
    """The reason a command edits protected files (REASON, BLIND, DEEP), ASK when it only writes docs instruction files, or None."""
    raw = _TRAILING.sub("/", raw.rstrip())
    if too_deep(raw):
        return DEEP
    asked: list[str] = []

    def firm(path: str) -> bool:
        kind = verdict(path)
        if kind == ASKED:
            asked.append(path)
        return kind == BLOCK

    if any(writes_files(cmd, firm) for cmd in commands(raw)) or refuses(raw, PROTECTED, firm, normalise):
        return REASON
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

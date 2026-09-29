#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse shell commands that write to CI/CD workflow config; reads and tool-driven writes pass.
# Best effort and coarse: a write must target a workflow, composite action or dependabot file (redirect, writer verb, in-place edit, git checkout/restore, cmdlet).

import os
import shlex
import sys

from chock_shellparse import commands, writes_files

MARKER = "chock: approved-config-change"
PROTECTED = (".github/workflows", ".github/actions", ".github/dependabot.yml", ".github/dependabot.yaml")
REASON = "shell write touching CI/CD workflow config is not allowed -- an agent must not weaken the automated checks that review its own work. Propose the change for human review, or approve by including 'chock: approved-config-change' in the command."


def hit(path: str) -> bool:
    """Whether a path names something this guard protects (backslashes read as slashes)."""
    normal = path.replace("\\", "/")
    return any(part in normal for part in PROTECTED)


def check(raw: str) -> str | None:
    """The reason a command edits protected files, or None; a human's marker in the command line passes."""
    if MARKER in raw:
        return None
    if any(writes_files(cmd, hit) for cmd in commands(raw)):
        return REASON
    return None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"protect-ci-workflows: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

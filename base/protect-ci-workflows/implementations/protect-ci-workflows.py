#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse shell commands that write to CI/CD workflow config; reads and tool-driven writes pass.
# Best effort and coarse: a write must target a workflow, composite action or dependabot file (redirect, writer verb, in-place edit, git checkout/restore, cmdlet).

import os
import re
import shlex
import sys

from chock_shellparse import commands, writes_files

PROTECTED = (".github/workflows", ".github/actions", ".github/dependabot.yml", ".github/dependabot.yaml")
REASON = "shell write touching CI/CD workflow config is refused -- an agent must not weaken the automated checks that review its own work. Ask the person to make the change from their own shell."


def fold(path: str) -> str:
    """The path as the filesystem reads it: slashes, no `//` or `/./`, `..` resolved, no trailing dots, spaces or stream suffix, lowercase."""
    normal = path.replace("\\", "/")
    previous = None
    while previous != normal:
        previous = normal
        normal = normal.replace("//", "/").replace("/./", "/")
    parts: list[str] = []
    for part in normal.lower().split("/"):
        if part == ".." and parts and parts[-1] not in ("", ".."):
            parts.pop()
            continue
        drive_or_dots = re.fullmatch(r"[a-z]:|\.+", part)
        parts.append(part if drive_or_dots else part.split(":", 1)[0].rstrip(". ") or part)
    return "/".join(parts)


def join(cwd: str, path: str) -> str:
    """`path` read from `cwd`, unless it is absolute or `cwd` is the repository root."""
    return path if not cwd or path.startswith(("/", "\\")) else f"{cwd}/{path}"


def hit(path: str, cwd: str = "") -> bool:
    """Whether a path, read from `cwd`, is protected, or is the `.github` folder that holds the protected ones."""
    normal = fold(join(cwd, path))
    return any(part in normal for part in PROTECTED) or normal.rstrip("/").rsplit("/", 1)[-1] == ".github"


def check(raw: str) -> str | None:
    """The reason a command edits protected files, or None; `cd`, `pushd` and `popd` move where later relative paths start."""
    cwd, saved = "", []
    for cmd in commands(raw):
        if cmd.name in ("cd", "pushd"):
            saved += [cwd] * (cmd.name == "pushd")
            cwd = join(cwd, next((arg for arg in cmd.args if not arg.startswith("-")), ""))
        elif cmd.name == "popd":
            cwd = saved.pop() if saved else ""
        elif writes_files(cmd, lambda path, here=cwd: hit(path, here)):
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

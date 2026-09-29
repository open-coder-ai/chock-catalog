#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse launching a coding agent (claude, codex, gemini, cursor-agent) with its permission and sandbox checks off.
# Best effort: the agent is recognised by program name (or its npx package), so an alias or a wrapper script is out of reach.

import os
import re
import shlex
import sys
from collections.abc import Callable

from chock_shellparse import Cmd, commands

# npx/bunx run a package by name: the package decides which agent starts.
LAUNCHERS = frozenset(("npx", "bunx", "pnpx"))
PACKAGES = {
    "@anthropic-ai/claude-code": "claude",
    "@openai/codex": "codex",
    "@google/gemini-cli": "gemini",
    "cursor-agent": "cursor-agent",
}
Check = Callable[[list[str]], str]


def value_of(args: list[str], flag: str) -> str:
    """The value a `--flag value` or `--flag=value` option carries, lowercased, or ''."""
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return args[i + 1].lower()
        if arg.startswith(f"{flag}="):
            return arg.split("=", 1)[1].lower()
    return ""


def has(args: list[str], *flags: str) -> bool:
    """Whether any of the flags is present, alone or as `--flag=value`."""
    return any(arg.split("=", 1)[0] in flags for arg in args if arg.startswith("-"))


def claude(args: list[str]) -> str:
    if has(args, "--dangerously-skip-permissions"):
        return "claude --dangerously-skip-permissions"
    return (
        "claude --permission-mode bypassPermissions"
        if value_of(args, "--permission-mode") == "bypasspermissions"
        else ""
    )


def codex(args: list[str]) -> str:
    for flag in ("--full-auto", "--yolo", "--dangerously-bypass-approvals-and-sandbox"):
        if has(args, flag):
            return f"codex {flag}"
    unsandboxed = "danger-full-access" in (value_of(args, "--sandbox"), value_of(args, "-s"))
    return "codex --sandbox danger-full-access" if unsandboxed else ""


def gemini(args: list[str]) -> str:
    if has(args, "--yolo", "-y"):
        return "gemini --yolo"
    return "gemini --approval-mode yolo" if value_of(args, "--approval-mode") == "yolo" else ""


def cursor_agent(args: list[str]) -> str:
    return "cursor-agent --force" if has(args, "--force", "-f") else ""


AGENTS: dict[str, Check] = {"claude": claude, "codex": codex, "gemini": gemini, "cursor-agent": cursor_agent}


def launched(cmd: Cmd) -> tuple[str, list[str]]:
    """(agent, its arguments) for a command that starts one, looking through `npx <package>`; else ('', [])."""
    if cmd.name in AGENTS:
        return cmd.name, cmd.args
    words = [arg for arg in cmd.args if not arg.startswith("-")]
    agent = PACKAGES.get(re.sub(r"(?<=.)@[^/@]*$", "", words[0])) if cmd.name in LAUNCHERS and words else None
    return (agent, cmd.args[cmd.args.index(words[0]) + 1 :]) if agent else ("", [])


def check(raw: str) -> str | None:
    """The unsafe launch a command line contains, or None."""
    for cmd in commands(raw):
        agent, args = launched(cmd)
        unsafe = AGENTS[agent](args) if agent else ""
        if unsafe:
            return (
                f"{unsafe} starts a coding agent with its safety checks off. Run it with its default approvals and "
                "sandbox, or a scoped allow-list; a human decides when an unattended, unsandboxed run is acceptable."
            )
    return None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(
            f"block-unguarded-agent-spawn: internal error ({type(exc).__name__}); command not checked", file=sys.stderr
        )
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

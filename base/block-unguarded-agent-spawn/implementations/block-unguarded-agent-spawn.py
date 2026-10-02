#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse launching a coding agent (claude, codex, gemini, cursor-agent, aider, copilot, amp, cline, goose, opencode) with
# its permission and sandbox checks off. Best effort: the agent is recognised by program name (or its npx/uvx package),
# so an alias or a wrapper script is out of reach, and each agent's flag list is the one its documentation names.

import os
import re
import shlex
import sys
from collections.abc import Callable

from chock_shellparse import Cmd, commands

# npx/bunx/uvx run a package by name: the package decides which agent starts.
LAUNCHERS = frozenset(("npx", "bunx", "pnpx", "uvx"))
PACKAGES = {
    "@anthropic-ai/claude-code": "claude",
    "@openai/codex": "codex",
    "@google/gemini-cli": "gemini",
    "cursor-agent": "cursor-agent",
    "@github/copilot": "copilot",
    "@sourcegraph/amp": "amp",
    "aider-chat": "aider",
    "cline": "cline",
    "opencode-ai": "opencode",
}
#: Flags that switch an agent's approvals off, for the agents whose flags are the same family of words.
GENERIC_FLAGS = (
    "--dangerously-skip-permissions",
    "--dangerously-allow-all",
    "--dangerously-bypass-approvals-and-sandbox",
    "--yolo",
    "--trust-all-tools",
    "--auto-approve",
    "--auto-approve-all",
    "--allow-all-tools",
    "--yes-always",
)
TOOL_FLAGS = frozenset(("--allowedTools", "--allowed-tools"))
WILDCARD_TOOL = re.compile(r"\*|[A-Za-z_][A-Za-z0-9_]*\(:?\*\)")
Check = Callable[[Cmd, list[str]], str]


def value_of(args: list[str], flag: str) -> str:
    """The value a `--flag value` or `--flag=value` option carries, lowercased, or ''."""
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return args[i + 1].lower()
        if arg.startswith(f"{flag}="):
            return arg.split("=", 1)[1].lower()
    return ""


def tool_lists(args: list[str]) -> list[str]:
    """The values of --allowedTools: the first may hold a list; later ones count only when they are one word, not a prompt."""
    found: list[str] = []
    for i, arg in enumerate(args):
        flag, eq, value = arg.partition("=")
        if flag not in TOOL_FLAGS:
            continue
        rest = args[i + 1 :]
        given = [value] if eq else rest[: next((n for n, word in enumerate(rest) if word.startswith("-")), len(rest))]
        found += given[:1] + [word for word in given[1:] if not re.search(r"\s", word)]
    return found


def has(args: list[str], *flags: str) -> bool:
    """Whether any of the flags is present, alone or as `--flag=value`."""
    return any(arg.split("=", 1)[0] in flags for arg in args if arg.startswith("-"))


def claude(_cmd: Cmd, args: list[str]) -> str:
    if has(args, "--dangerously-skip-permissions"):
        return "claude --dangerously-skip-permissions"
    if value_of(args, "--permission-mode") == "bypasspermissions":
        return "claude --permission-mode bypassPermissions"
    for value in tool_lists(args):
        if any(WILDCARD_TOOL.fullmatch(tool) for tool in re.split(r"[,\s]+", value) if tool):
            return "claude --allowedTools with a wildcard"
    return ""


def codex(_cmd: Cmd, args: list[str]) -> str:
    for flag in ("--full-auto", "--yolo", "--dangerously-bypass-approvals-and-sandbox"):
        if has(args, flag):
            return f"codex {flag}"
    if "never" in (value_of(args, "--ask-for-approval"), value_of(args, "-a")):
        return "codex --ask-for-approval never"
    unsandboxed = "danger-full-access" in (value_of(args, "--sandbox"), value_of(args, "-s"))
    return "codex --sandbox danger-full-access" if unsandboxed else ""


def gemini(_cmd: Cmd, args: list[str]) -> str:
    if has(args, "--yolo", "-y"):
        return "gemini --yolo"
    return "gemini --approval-mode yolo" if value_of(args, "--approval-mode") == "yolo" else ""


def cursor_agent(_cmd: Cmd, args: list[str]) -> str:
    return "cursor-agent --force" if has(args, "--force", "-f") else ""


def aider(_cmd: Cmd, args: list[str]) -> str:
    return "aider --yes-always" if has(args, "--yes-always", "--yes") else ""


def copilot(_cmd: Cmd, args: list[str]) -> str:
    flag = next((flag for flag in ("--allow-all-tools", "--allow-all", "--yolo") if has(args, flag)), "")
    return f"copilot {flag}" if flag else ""


def generic(name: str, *extra: str) -> Check:
    """The check for an agent whose auto-approve flags are the shared family, plus its own short ones."""

    def check(cmd: Cmd, args: list[str]) -> str:
        flag = next((flag for flag in (*GENERIC_FLAGS, *extra) if has(args, flag)), "")
        if not flag and name == "goose" and cmd.env.get("GOOSE_MODE", "").lower() == "auto":
            flag = "GOOSE_MODE=auto"
        return f"{name} {flag}" if flag else ""

    return check


AGENTS: dict[str, Check] = {
    "claude": claude,
    "codex": codex,
    "gemini": gemini,
    "cursor-agent": cursor_agent,
    "aider": aider,
    "copilot": copilot,
    "amp": generic("amp"),
    "cline": generic("cline", "-y"),
    "goose": generic("goose"),
    "opencode": generic("opencode"),
}


def launched(cmd: Cmd) -> tuple[str, list[str]]:
    """(agent, its arguments) for a command that starts one, looking through `npx <package>`; else ('', [])."""
    if cmd.name in AGENTS:
        return cmd.name, cmd.args
    words = [arg for arg in cmd.args if not arg.startswith("-")]
    package = re.sub(r"(?<=.)(?:@[^/@]*|==.*)$", "", words[0]) if words else ""
    agent = PACKAGES.get(package) if cmd.name in LAUNCHERS else None
    return (agent, cmd.args[cmd.args.index(words[0]) + 1 :]) if agent else ("", [])


def check(raw: str) -> str | None:
    """The unsafe launch a command line contains, or None; every command of a pipeline or list is judged."""
    for cmd in commands(raw):
        agent, args = launched(cmd)
        unsafe = AGENTS[agent](cmd, args) if agent else ""
        if unsafe:
            return (
                f"{unsafe} starts a coding agent with its safety checks off. Run it with its default approvals and "
                "sandbox, or a scoped allow-list. If an unattended, unsandboxed run is needed, ask the person; they start it "
                "from their own shell."
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

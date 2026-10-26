#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Gate MCP server configuration as protected content: `<agent> mcp add` and a shell write to a dedicated MCP config are
# refused unless every server they name is on the allowlist (.chock/mcp-allowlist.json, as HEAD holds it). The pin, shell,
# https, credential and option rules are the gate's, and only warn. A shell write to the allowlist or this guard is refused.

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from chock_shellparse import Cmd, commands, writes_files
from mcpcheck import allowlist, configs, entry, rules
from mcpcheck.mcpadd import added_server, parse_add  # noqa: F401 -- parse_add is the tested surface of the guard

GUARD_SOURCE = re.compile(r"verify-mcp-allowlist(/implementations|\.(sh|py))")
SHELL_NAMES = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash"})
INTERPRETERS = ("python", "perl", "ruby", "node", "php")
CODE_FLAG = re.compile(r"-[A-Za-z]*[cepErR]|--(?:eval|print|command)")
ECHO_FLAG = re.compile(r"-[neE]+")
#: The format `%s\n` also reads as `%s/n`: the shared reader emits a second, Windows-path reading of the same line.
PRINTF_WHOLE = re.compile(r"%[sb](?:[\\/]n)?\n?")
PRINTF_FORMAT_AND_TEXT = 2
GIT = shutil.which("git") or "git"
NO_ENTRY = (
    "this command writes an MCP config but no server entry is visible on the command line to verify against the allowlist. "
    "Write the full content inline as JSON, or ask the person to make the change from their own shell."
)
REFUSED = (
    "MCP server config change refused -- {why}. Only servers on the allowlist ({path}: name with launcher and exact "
    "arguments, or url host) may be added. Do not edit the allowlist or add the server yourself; ask the person to "
    "review it and edit the allowlist from their own shell."
)


def is_guard(path: str) -> bool:
    """The guard's own source, or the allowlist file (matched without regard to case or slash)."""
    return GUARD_SOURCE.search(path.replace("\\", "/")) is not None or configs.rooted(path).endswith(
        "/" + allowlist.PATH
    )


def own_text(cmd: Cmd) -> str | None:
    """The whole text an echo, printf or `cat <<EOF` writes, when its own argument or here-document is all of it."""
    args = list(cmd.args)
    if cmd.name == "echo":
        while args and ECHO_FLAG.fullmatch(args[0]):
            args.pop(0)
        return " ".join(args) if args and not cmd.doc else None
    if cmd.name == "printf" and not cmd.doc and args:
        if "%" not in args[0]:
            return args[0] if len(args) == 1 else None
        return args[1] if len(args) == PRINTF_FORMAT_AND_TEXT and PRINTF_WHOLE.fullmatch(args[0]) else None
    if cmd.name == "cat" and cmd.doc and all(arg == "-" for arg in args):
        return cmd.doc
    return None


def written_servers(cmds: list[Cmd]) -> list[tuple[str, object]] | None:
    """(name, entry) for the servers the commands that write a config carry as their whole text; None when one writes bytes the line does not show."""
    found: list[tuple[str, object]] = []
    for cmd in cmds:
        if not (writes_files(cmd, configs.is_dedicated) or code_names(cmd, configs.DEDICATED)):
            continue
        text = own_text(cmd)
        try:
            value = json.loads(text) if text is not None else None
        except (ValueError, RecursionError):
            value = None
        servers = [
            (str(name), config)
            for key in configs.COMMON
            if isinstance(value, dict) and isinstance(block := value.get(key), dict)
            for name, config in block.items()
        ]
        if not servers:
            return None
        found += servers
    return found


def judged(found: list[tuple[str, object]], allowed: tuple[allowlist.Allowed, ...]) -> str | None:
    """The first reason a server is refused, or None when every one is on the allowlist and passes every rule."""
    for name, config in found:
        try:
            problems = rules.judge(entry.from_config(name, config), allowed)
        except entry.EntryError as exc:
            return f"server {name!r}: {exc}, so it cannot be verified"
        except RecursionError:
            return f"server {name!r}: nested too deeply to read, so it cannot be verified"
        if refused := [message for rule, message in problems if rule in rules.ENFORCED]:
            return f"server {name!r}: {refused[0]}"
    return None


def runs_code(cmd: Cmd) -> bool:
    """Whether a command is an interpreter (python, node, perl, ruby, php) given code inline or on stdin."""
    return cmd.name.startswith(INTERPRETERS) and (bool(cmd.doc) or any(CODE_FLAG.fullmatch(arg) for arg in cmd.args))


def code_names(cmd: Cmd, names: tuple[str, ...]) -> bool:
    """Whether the code an interpreter runs inline names one of these paths as a whole file name (any case, either slash)."""
    if not runs_code(cmd):
        return False
    text = "\n".join((*cmd.args, cmd.doc)).lower().replace("\\", "/")
    return any(re.search(rf"(?<![\w.-]){re.escape(name.lower())}(?![\w.-])", text) for name in names)


def reads_script_from_stdin(cmd: Cmd) -> bool:
    """A shell given a heredoc and no script file or `-c` text: the heredoc is what it runs."""
    options = all(arg.startswith("-") and (arg.startswith("--") or "c" not in arg) for arg in cmd.args)
    return cmd.name in SHELL_NAMES and bool(cmd.doc) and options


def shell_input(cmds: list[Cmd]) -> list[Cmd]:
    """The commands, plus those a shell runs from a heredoc given to it (`bash <<EOF`)."""
    found = list(cmds)
    for cmd in cmds:
        if reads_script_from_stdin(cmd):
            found += shell_input(commands(cmd.doc))
    return found


def repo_root() -> Path:
    """The enclosing git work tree, or the current directory when there is none."""
    try:
        out = subprocess.run(  # noqa: S603 -- read-only git with a fixed argument list
            [GIT, "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=20, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return Path.cwd()
    return Path(out.stdout.strip()) if out.returncode == 0 and out.stdout.strip() else Path.cwd()


def check(raw: str) -> str | None:
    """The reason a command changes MCP configuration outside the allowlist, or None."""
    cmds = shell_input(commands(raw))
    protected = (allowlist.PATH,)
    if any(writes_files(cmd, is_guard) or code_names(cmd, protected) for cmd in cmds):
        return (
            "shell write to the MCP server allowlist is refused -- it is protected content, the same way "
            "protect-agent-config protects every policy's guard source. Ask the person to make the change."
        )
    adds = [added for cmd in cmds if (added := added_server(cmd)) is not None]
    written = written_servers(cmds)
    if written is None:
        return NO_ENTRY
    if not adds and not written:
        return None
    try:
        allowed, _ = allowlist.load(repo_root(), "tool_use")
    except allowlist.AllowlistError as exc:
        return REFUSED.format(why=f"the MCP allowlist is {exc}", path=allowlist.PATH)
    opaque = any(config is None and not name for name, config in adds)
    why = (
        "a command that adds an MCP server cannot be read, so it cannot be verified"
        if opaque
        else judged([*adds, *written], allowed)
    )
    return REFUSED.format(why=why, path=allowlist.PATH) if why else None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except RecursionError:
        print("BLOCKED: the command is nested too deeply to be read, so it cannot be verified.", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"verify-mcp-allowlist: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

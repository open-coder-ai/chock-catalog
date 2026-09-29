#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Gate MCP server configuration as protected content: a shell write to .mcp.json, or `claude mcp add|add-json`, is
# refused unless every server it names matches a name+source pair on the allowlist below. The allowlist lives in THIS
# script, so a shell edit to it is refused like any edit to a policy guard -- unless the command carries the
# 'chock: approved-config-change' marker. Best effort: tool-time (shell) only, Claude Code's .mcp.json only.

import json
import os
import re
import shlex
import sys

from chock_shellparse import Cmd, commands, writes_files

# The allowlist IS the policy: maintainer-approved MCP servers, name -> source, where source is the launch command and
# its args (space-joined, in order) or the url of a remote server. Matching is exact. Add your own; ships with the
# official MCP reference filesystem server as a worked example.
ALLOWED_MCP_SERVERS = {"filesystem": "npx -y @modelcontextprotocol/server-filesystem"}
MARKER = "chock: approved-config-change"
CONFIG = ".mcp.json"
GUARD_SOURCE = re.compile(r"verify-mcp-allowlist(/implementations|\.(sh|py))")
ADD_VALUE_FLAGS = frozenset(("-s", "--scope", "-t", "--transport", "-e", "--env", "-H", "--header"))
NO_ENTRY = (
    f"this command writes {CONFIG} but no server entry is visible on the command line to verify against the allowlist. "
    "Write the full content inline as JSON, or have a human approve with 'chock: approved-config-change'."
)


def is_config(path: str) -> bool:
    return CONFIG in path.replace("\\", "/")


def is_guard(path: str) -> bool:
    return GUARD_SOURCE.search(path.replace("\\", "/")) is not None


def source_of(config: object) -> str:
    """The launch command with its args, or the url, of one server entry as an .mcp.json object carries it."""
    if not isinstance(config, dict):
        return ""
    command, args = config.get("command"), config.get("args")
    if isinstance(command, str) and command:
        return " ".join([command, *(a for a in args if isinstance(a, str))] if isinstance(args, list) else [command])
    url = config.get("url")
    return url if isinstance(url, str) else ""


def json_objects(text: str) -> list[dict]:
    """Every JSON object a piece of text is, or holds between its first `{` and last `}`."""
    found = []
    for candidate in (text.strip(), text[text.find("{") : text.rfind("}") + 1]):
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(value, dict):
            found.append(value)
    return found


def entries(cmds: list[Cmd]) -> list[tuple[str, str]]:
    """(name, source) for every mcpServers entry any command in the line carries as JSON."""
    found = []
    for cmd in cmds:
        for text in (cmd.doc, *cmd.args):
            for obj in json_objects(text):
                servers = obj.get("mcpServers")
                if isinstance(servers, dict):
                    found += [(str(name), source_of(config)) for name, config in servers.items()]
    return found


def cli_entries(cmd: Cmd) -> list[tuple[str, str]] | None:
    """(name, source) for `claude mcp add|add-json`; None when it is not one; add-from-claude-desktop is opaque."""
    if (
        cmd.name != "claude"
        or cmd.args[:1] != ["mcp"]
        or cmd.args[1:2] not in (["add"], ["add-json"], ["add-from-claude-desktop"])
    ):
        return None
    verb, args = cmd.args[1], cmd.args[2:]
    if "--" in args:
        args, launch = args[: args.index("--")], args[args.index("--") + 1 :]
    else:
        launch = []
    words, skip = [], False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-"):
            skip = arg in ADD_VALUE_FLAGS
        else:
            words.append(arg)
    if verb == "add-from-claude-desktop" or not words:
        return [("(opaque)", "")]
    if verb == "add-json":
        objs = json_objects(words[1]) if len(words) > 1 else []
        return [(words[0], source_of(objs[0]) if objs else "")]
    return [(words[0], " ".join(launch or words[1:]))]


def unlisted(found: list[tuple[str, str]]) -> str | None:
    """The reason an entry is refused, or None when every one matches the allowlist exactly."""
    for name, source in found:
        if name not in ALLOWED_MCP_SERVERS:
            return f"'{name}' is not on the allowlist"
        if source.strip() != ALLOWED_MCP_SERVERS[name].strip():
            return f"'{name}' is on the allowlist, but its command/args/url do not match the allowlisted entry"
    return None


REFUSED = (
    "MCP server config change refused -- {why}. Add or fix the entry (name + exact source) in the allowlist at the top "
    "of implementations/verify-mcp-allowlist.py via a human-approved 'chock: approved-config-change' edit."
)


def check(raw: str) -> str | None:
    """The reason a command changes MCP configuration outside the allowlist, or None."""
    if MARKER in raw:
        return None
    cmds = commands(raw)
    if any(writes_files(cmd, is_guard) for cmd in cmds):
        return (
            "shell write to the MCP server allowlist is not allowed -- it is protected content, the same way "
            "protect-agent-config protects every policy's guard source. Have a human approve by including "
            "'chock: approved-config-change' in the command."
        )
    found = [pair for cmd in cmds for pair in (cli_entries(cmd) or [])]
    if any(writes_files(cmd, is_config) for cmd in cmds):
        written = entries(cmds)
        if not written:
            return NO_ENTRY
        found += written
    why = unlisted(found)
    return REFUSED.format(why=why) if why else None


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        reason = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"verify-mcp-allowlist: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

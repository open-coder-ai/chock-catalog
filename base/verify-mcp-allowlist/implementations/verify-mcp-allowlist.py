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

GUARD_SOURCE = re.compile(r"verify-mcp-allowlist(/implementations|\.(sh|py))")
#: agent program -> the `mcp` verbs that add a server
ADD_VERBS = {
    "claude": ("add", "add-json", "add-from-claude-desktop"),
    "codex": ("add",),
    "gemini": ("add",),
    "cursor-agent": ("add",),
}
VALUE_FLAGS = frozenset(
    {
        "-s",
        "--scope",
        "-t",
        "--transport",
        "--url",
        "--bearer-token-env-var",
        "--callback-port",
        "--client-id",
        "--client-secret",
        "--timeout",
        "--description",
        "--header-env",
    }
)
PACKAGE_RUNNERS = frozenset({"npx", "bunx", "pnpx", "uvx", "npm", "pnpm", "yarn", "bun"})
BARE_AGENTS = frozenset({"claude", "codex", "gemini", "cursor-agent"})
PACKAGE_AGENT = re.compile(r"(?:^|/)(claude-code|codex|gemini-cli)(?:@[^/@]*)?$")
PACKAGE_NAMES = {"claude-code": "claude", "codex": "codex", "gemini-cli": "gemini"}
LIST_FLAGS = {"-e": "env", "--env": "env", "-H": "header", "--header": "header"}
ENV_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
REMOTE = frozenset({"http", "sse", "streamable-http"})
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


def inline_servers(cmds: list[Cmd]) -> list[tuple[str, object]]:
    """(name, entry) for every server any command in the line carries as JSON under a servers key."""
    found: list[tuple[str, object]] = []
    for cmd in cmds:
        for text in (cmd.doc, *cmd.args):
            for obj in json_objects(text):
                for key in configs.COMMON:
                    block = obj.get(key)
                    found += [(str(name), config) for name, config in block.items()] if isinstance(block, dict) else []
    return found


def parse_add(args: list[str]) -> tuple[list[str], list[str], dict[str, list[str]], dict[str, str]]:
    """(positional words, the command after `--`, the -e and -H values, other flags' values) of an `mcp add` line."""
    head, launch = (args[: args.index("--")], args[args.index("--") + 1 :]) if "--" in args else (args, [])
    words: list[str] = []
    lists: dict[str, list[str]] = {"env": [], "header": []}
    flags: dict[str, str] = {}
    i = 0
    while i < len(head):
        flag, eq, value = head[i].partition("=")
        if flag in LIST_FLAGS:
            target = lists[LIST_FLAGS[flag]]
            if eq:
                target.append(value)
            elif i + 1 < len(head):
                i += 1
                target.append(head[i])
                while (
                    i + 1 < len(head)
                    and not head[i + 1].startswith("-")
                    and (ENV_WORD.match(head[i + 1]) or ": " in head[i + 1])
                ):
                    i += 1
                    target.append(head[i])
        elif flag in VALUE_FLAGS:
            flags[flag] = value if eq else (head[i + 1] if i + 1 < len(head) else "")
            i += 0 if eq else 1
        elif words or not head[i].startswith("-"):
            words.append(head[i])
        i += 1
    return words, launch, lists, flags


def added_server(cmd: Cmd) -> tuple[str, object] | None:
    """(name, entry) for an `<agent> mcp add*` command; ('', None) when it cannot be read; None when it is not one."""
    agent = cmd.name if cmd.name in ADD_VERBS else None
    if cmd.name in PACKAGE_RUNNERS:
        found = next((m for arg in cmd.args if (m := PACKAGE_AGENT.search(arg))), None)
        bare = next((arg for arg in cmd.args if arg in BARE_AGENTS), None)
        agent = PACKAGE_NAMES[found.group(1)] if found else bare
    if agent is None:
        return None
    # `mcp` may follow global options (`claude --model x mcp add ...`), so the first `mcp <verb>` pair is the one.
    at = next((i for i, arg in enumerate(cmd.args[:-1]) if arg == "mcp" and cmd.args[i + 1] in ADD_VERBS[agent]), None)
    if at is None:
        return None
    verb = cmd.args[at + 1]
    words, launch, lists, flags = parse_add(cmd.args[at + 2 :])
    if verb == "add-from-claude-desktop" or not words:
        return "", None
    if verb == "add-json":
        objs = json_objects(words[1]) if len(words) > 1 else []
        return words[0], objs[0] if objs else None
    config: dict = {}
    if "--url" in flags or flags.get("--transport", flags.get("-t", "")).lower() in REMOTE:
        config["url"] = flags.get("--url") or (words[1] if len(words) > 1 else "")
    else:
        command = launch or words[1:]
        config.update(command=command[0] if command else "", args=command[1:])
    config["env"] = dict(kv.partition("=")[::2] for kv in lists["env"])
    config["headers"] = {k.strip(): v.strip() for k, _, v in (h.partition(":") for h in lists["header"])}
    return words[0], config


def judged(found: list[tuple[str, object]], allowed: tuple[allowlist.Allowed, ...]) -> str | None:
    """The first reason a server is refused, or None when every one is on the allowlist and passes every rule."""
    for name, config in found:
        try:
            problems = rules.judge(entry.from_config(name, config), allowed)
        except entry.EntryError as exc:
            return f"server {name!r}: {exc}, so it cannot be verified"
        if refused := [message for rule, message in problems if rule in rules.ENFORCED]:
            return f"server {name!r}: {refused[0]}"
    return None


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
    cmds = commands(raw)
    if any(writes_files(cmd, is_guard) for cmd in cmds):
        return (
            "shell write to the MCP server allowlist is refused -- it is protected content, the same way "
            "protect-agent-config protects every policy's guard source. Ask the person to make the change."
        )
    adds = [added for cmd in cmds if (added := added_server(cmd)) is not None]
    writing = any(writes_files(cmd, configs.is_dedicated) for cmd in cmds)
    written = inline_servers(cmds) if writing else []
    if writing and not written:
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
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"verify-mcp-allowlist: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if reason:
        print(f"BLOCKED: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

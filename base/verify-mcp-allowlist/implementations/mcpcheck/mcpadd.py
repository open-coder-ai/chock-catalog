"""Reading an `<agent> mcp add` command line into the server entry it would write."""

from __future__ import annotations

import json
import re

from chock_shellparse import Cmd

#: agent program -> the `mcp` verbs that add a server
ADD_VERBS = {
    "claude": ("add", "add-json", "add-from-claude-desktop"),
    "codex": ("add",),
    "gemini": ("add",),
    "cursor-agent": ("add",),
    "agent": ("add",),
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
BARE_AGENTS = frozenset({"claude", "codex", "gemini", "cursor-agent", "agent"})
EXECUTABLE = re.compile(r"\.(?:exe|cmd|bat|ps1|com)$")
HELP_FLAGS = frozenset({"-h", "--help"})
PACKAGE_AGENT = re.compile(r"(?:^|/)(claude-code|codex|gemini-cli)(?:@[^/@]*)?$")
PACKAGE_NAMES = {"claude-code": "claude", "codex": "codex", "gemini-cli": "gemini"}
LIST_FLAGS = {"-e": "env", "--env": "env", "-H": "header", "--header": "header"}
ENV_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
REMOTE = frozenset({"http", "sse", "streamable-http"})


def json_objects(text: str) -> list[dict]:
    """Every JSON object a piece of text is, or holds between its first `{` and last `}`; none when it nests too deep."""
    found = []
    for candidate in (text.strip(), text[text.find("{") : text.rfind("}") + 1]):
        try:
            value = json.loads(candidate)
        except (ValueError, RecursionError):
            continue
        if isinstance(value, dict):
            found.append(value)
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
    name = EXECUTABLE.sub("", cmd.name.lower())
    agent = name if name in ADD_VERBS else None
    if name in PACKAGE_RUNNERS:
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
    rest = cmd.args[at + 2 :]
    if HELP_FLAGS & set(rest[: rest.index("--")] if "--" in rest else rest):
        return None
    words, launch, lists, flags = parse_add(rest)
    if verb == "add-from-claude-desktop" or not words:
        return "", None
    if verb == "add-json":
        objs = json_objects(words[1]) if len(words) > 1 else []
        return words[0], objs[0] if objs else None
    config: dict = {}
    transport = flags.get("--transport", flags.get("-t", "")).lower()
    if transport:
        config["type"] = transport
    if "--url" in flags or transport in REMOTE:
        config["url"] = flags.get("--url") or (words[1] if len(words) > 1 else "")
    else:
        command = launch or words[1:]
        config.update(command=command[0] if command else "", args=command[1:])
    config["env"] = dict(kv.partition("=")[::2] for kv in lists["env"])
    config["headers"] = {k.strip(): v.strip() for k, _, v in (h.partition(":") for h in lists["header"])}
    return words[0], config

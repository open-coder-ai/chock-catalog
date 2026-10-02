"""Agent configs that run commands or widen approval: Claude Code, Cursor, hook files and command front matter."""

from __future__ import annotations

import re

from devenv.commands import env_overrides, run
from devenv.core import Collector, dotted, norm, walk
from devenv.parse import UnreadableError, front_matter, json_value, yaml_leaves

HOOKS, ENV, APPROVE = "dev-claude-hooks", "dev-claude-env-override", "dev-mcp-autoapprove"

#: Keys whose string value is a command a hook runner executes (Claude, Cursor, Codex, Copilot, Gemini, Kiro).
COMMAND_KEYS = frozenset({"command", "commandWindows", "bash", "powershell", "windows", "linux", "osx"})
#: Claude Code settings whose value is a command it runs at start or refresh.
HELPERS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "gcpAuthRefresh")
HELPER_OBJECTS = ("statusLine", "subagentStatusLine", "fileSuggestion")


def object_of(text: str) -> dict:
    value = json_value(text)
    if not isinstance(value, dict):
        msg = "the top level is not an object"
        raise UnreadableError(msg)
    return value


def truthy(value: object) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in ("true", "yes", "on", "1"))


def hook_commands(c: Collector, where: str, hooks: object) -> None:
    """Every command or URL a hook table runs, whatever the vendor's nesting."""
    for path, leaf in walk(hooks):
        if not path or not isinstance(leaf, str):
            continue
        key = str(path[-1])
        spot = f"{where}.{dotted(path)}"
        if key in COMMAND_KEYS:
            run(c, HOOKS, spot, leaf, "hook command")
        elif key == "url":
            c.add(HOOKS, f"{spot}={norm(leaf)}", f"HTTP hook at {spot}", line=c.line_of(leaf))


def approve(c: Collector, where: str, what: str, *, value: object = True) -> None:
    c.add(APPROVE, f"{where}={norm(value)}", f"{what} at {where}", line=c.line_of(where.rsplit(".", 1)[-1]))


def claude_settings(c: Collector) -> None:
    settings = object_of(c.text)
    hook_commands(c, "hooks", settings.get("hooks"))
    for name in HELPERS:
        if isinstance(settings.get(name), str):
            run(c, HOOKS, name, settings[name], "credential or telemetry helper command")
    for name in HELPER_OBJECTS:
        block = settings.get(name)
        if isinstance(block, dict) and isinstance(block.get("command"), str):
            run(c, HOOKS, f"{name}.command", block["command"], "status or suggestion command")
    env_overrides(c, ENV, "env", settings.get("env"))
    if truthy(settings.get("enableAllProjectMcpServers")):
        approve(c, "enableAllProjectMcpServers", "every project MCP server enabled without review")
    servers = settings.get("enabledMcpjsonServers")
    for name in servers if isinstance(servers, list) else []:
        approve(c, "enabledMcpjsonServers", "project MCP server approved in advance", value=name)
    for flag in ("disableAllHooks", "skipDangerousModePermissionPrompt", "dangerouslySkipPermissions"):
        if truthy(settings.get(flag)):
            approve(c, flag, "guard hooks or permission prompts switched off")


_INLINE = re.compile(r"!`([^`\n]+)`")
_UNSCOPED = re.compile(r"(?i)^(?:bash|shell|powershell|\*)$")


def claude_markdown(c: Collector) -> None:
    """A command, agent or skill file: tools granted in front matter, hooks there, and inline `!` shell lines."""
    found = front_matter(c.text)
    if found is not None:
        body, offset = found
        for path, value, line in yaml_leaves(body):
            key = str(path[0])
            spot = dotted(path)
            if key in ("allowed-tools", "tools"):
                for tool in re.split(r"[,\s]+", value):
                    if _UNSCOPED.fullmatch(tool.strip("'\"[]")):
                        c.add(APPROVE, f"{key}={tool}", f"unscoped tool grant {tool} at {spot}", line=line + offset)
            elif key == "permissionMode" and value.strip() in ("bypassPermissions", "dontAsk"):
                c.add(APPROVE, f"{key}={value}", f"permission prompts skipped at {spot}", line=line + offset)
            elif key == "hooks" and str(path[-1]) in COMMAND_KEYS:
                run(c, HOOKS, spot, value, "hook command in front matter", line=line + offset)
    for match in _INLINE.finditer(c.text):
        line = c.text.count("\n", 0, match.start()) + 1
        run(c, HOOKS, "inline-shell", match.group(1), "inline shell the command runs", line=line)


def hooks_file(c: Collector) -> None:
    hook_commands(c, "hooks", object_of(c.text))


def cursor_environment(c: Collector) -> None:
    """Cursor background agents run `install` and `start` on boot, and each terminal's command."""
    config = object_of(c.text)
    for key in ("install", "start", "build"):
        if isinstance(config.get(key), str):
            run(c, HOOKS, key, config[key], "background-agent command")
    terminals = config.get("terminals")
    for index, terminal in enumerate(terminals if isinstance(terminals, list) else []):
        if isinstance(terminal, dict) and isinstance(terminal.get("command"), str):
            run(c, HOOKS, f"terminals.{index}.command", terminal["command"], "background-agent terminal")


_WIDE_GRANT = re.compile(r"(?i)^(?:shell|bash|write|edit|read|mcp)(?:\(\s*(?:\*|\*\*|\*:\*|/\*\*)\s*\))?$")


def cursor_cli(c: Collector) -> None:
    allow = object_of(c.text).get("permissions", {})
    entries = allow.get("allow") if isinstance(allow, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, str) and _WIDE_GRANT.fullmatch(entry.strip()):
            approve(c, f"permissions.allow.{entry.strip()}", "unscoped tool grant", value=entry)

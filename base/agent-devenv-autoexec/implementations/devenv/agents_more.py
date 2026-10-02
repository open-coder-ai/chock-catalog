"""More agent configs: Gemini CLI, Codex, MCP client files, aider, opencode and agent dotenv files."""

from __future__ import annotations

import re

from devenv.agents import APPROVE, ENV, HOOKS, approve, hook_commands, object_of, truthy
from devenv.commands import dangerous_env, env_overrides, run
from devenv.core import Collector, dotted, norm, strings, walk
from devenv.parse import toml_value, yaml_leaves


def gemini_settings(c: Collector) -> None:
    settings = object_of(c.text)
    hook_commands(c, "hooks", settings.get("hooks"))
    tools = settings.get("tools") if isinstance(settings.get("tools"), dict) else {}
    for scope, block in (("", settings), ("tools.", tools)):
        for key in ("discoveryCommand", "callCommand", "toolDiscoveryCommand", "toolCallCommand"):
            if isinstance(block.get(key), str):
                run(c, HOOKS, f"{scope}{key}", block[key], "tool discovery or call command")
        if truthy(block.get("autoAccept")):
            approve(c, f"{scope}autoAccept", "tool calls accepted without a prompt")
    for path, leaf in walk(settings):
        key = str(path[-1]) if path else ""
        if key == "trust" and truthy(leaf) and "mcpServers" in path:
            approve(c, dotted(path), "MCP server trusted, so its tool calls skip confirmation")
        elif key in ("approvalMode", "defaultApprovalMode") and str(leaf).lower() in ("yolo", "auto_edit"):
            approve(c, dotted(path), "approval mode that skips confirmation", value=leaf)
        elif path[-2:] == ("folderTrust", "enabled") and leaf is False:
            approve(c, dotted(path), "folder trust switched off", value=leaf)


_DOTENV = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def agent_dotenv(c: Collector) -> None:
    """An agent's own .env (Gemini CLI loads `.gemini/.env`): the same redirecting names as settings `env`."""
    env = {}
    for line in c.lines:
        found = _DOTENV.match(line)
        if found:
            env[found.group(1)] = found.group(2).strip()
    env_overrides(c, ENV, "dotenv", env)


_CODEX_URLS = frozenset({"base_url", "openai_base_url", "chatgpt_base_url", "experimental_base_url"})


def codex_config(c: Collector) -> None:
    config = toml_value(c.text)
    for path, leaf in walk(config):
        key = str(path[-1]) if path else ""
        spot = dotted(path)
        if key == "approval_policy" and leaf == "never":
            approve(c, spot, "approval policy that never asks", value=leaf)
        elif key == "sandbox_mode" and leaf == "danger-full-access":
            approve(c, spot, "sandbox switched off", value=leaf)
        elif key in _CODEX_URLS:
            c.add(ENV, f"{spot}={norm(leaf)}", f"model endpoint override at {spot}", line=c.line_of(key))
        elif path[-3:-1] == ("shell_environment_policy", "set") and dangerous_env(key):
            c.add(ENV, f"{spot}={norm(leaf)}", f"environment override {key} at {spot}", line=c.line_of(key))
    for scope, block in [("", config), *((f"profiles.{n}.", p) for n, p in _profiles(config))]:
        for text in strings(block.get("notify")):
            run(c, HOOKS, f"{scope}notify", text, "notify program")


def _profiles(config: dict) -> list[tuple[str, dict]]:
    profiles = config.get("profiles")
    return [(n, p) for n, p in profiles.items() if isinstance(p, dict)] if isinstance(profiles, dict) else []


def mcp_client(c: Collector) -> None:
    """Approval an MCP client file grants ahead of time (the servers themselves are verify-mcp-allowlist's)."""
    for path, leaf in walk(object_of(c.text)):
        if not path:
            continue
        holder = next((str(p) for p in path if p in ("autoApprove", "alwaysAllow")), None)
        if holder and isinstance(leaf, str):
            approve(c, f"{dotted(path[: path.index(holder) + 1])}", "MCP tool approved in advance", value=leaf)
        elif holder and leaf is True:
            approve(c, dotted(path), "MCP tools approved in advance", value=leaf)
        elif path[-1] == "trust" and truthy(leaf):
            approve(c, dotted(path), "MCP server trusted, so its tool calls skip confirmation")


def aider_config(c: Collector) -> None:
    for path, value, line in yaml_leaves(c.text):
        key = str(path[0])
        if key == "yes-always" and truthy(value):
            c.add(APPROVE, f"{key}={value}", "every aider prompt answered yes", line=line)
        elif key in ("test-cmd", "lint-cmd"):
            run(c, HOOKS, dotted(path), value, "command aider runs after each edit", severity="ask", line=line)
        elif re.fullmatch(r"(?:[a-z]+-)?api-base", key):
            c.add(ENV, f"{key}={norm(value)}", f"model endpoint override at {key}", line=line)


def opencode_config(c: Collector) -> None:
    permission = object_of(c.text).get("permission")
    for path, leaf in walk(permission):
        wide = path and (path[0] in ("bash", "external_directory") or "*" in map(str, path))
        if wide and leaf == "allow":
            approve(
                c, f"permission.{dotted(path)}", "shell or outside-repo access allowed without a prompt", value=leaf
            )

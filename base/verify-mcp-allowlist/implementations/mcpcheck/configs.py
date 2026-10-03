"""The MCP client config files the gate reads, and the server entries and enable switches each one holds."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import tomllib
from dataclasses import dataclass, field

from chock_scan import jsonc

COMMON = ("mcpServers", "servers")
#: Dedicated MCP files: a shell write to one is judged by the command guard too (the others hold unrelated settings).
DEDICATED = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp_config.json",
    ".roo/mcp.json",
    ".kiro/settings/mcp.json",
    "claude_desktop_config.json",
)
#: path suffix (lowercase) -> (kind, containers that hold server entries)
SUFFIXES = {
    **{name: ("json", COMMON) for name in (*DEDICATED, ".gemini/settings.json")},
    ".zed/settings.json": ("json", ("context_servers",)),
    "opencode.json": ("json", ("mcp",)),
    "opencode.jsonc": ("json", ("mcp",)),
    ".codex/config.toml": ("toml", ("mcp_servers",)),
}
CLAUDE_SETTINGS = re.compile(r"/\.claude/settings[^/]*\.json")
ENABLE_ALL = "enableAllProjectMcpServers"
ENABLED = "enabledMcpjsonServers"
MAX_SERVER_DEPTH = 2


@dataclass(frozen=True)
class Config:
    """How to read one config path: `kind` json or toml, the `containers` that hold servers, `claude` for settings files."""

    kind: str
    containers: tuple[str, ...]
    claude: bool = False


@dataclass
class Parsed:
    """`servers` are (name, entry) as declared, repeats included; `problems` are (rule, key, message) for the file."""

    servers: list[tuple[str, object]] = field(default_factory=list)
    problems: list[tuple[str, str, str]] = field(default_factory=list)


def rooted(path: str) -> str:
    """A path as the matchers see it: lowercase, forward slashes, rooted, `.`, `..` and `//` resolved, no trailing dots or spaces."""
    return "/" + posixpath.normpath(path.replace("\\", "/").lower().rstrip(". ")).lstrip("/")


def config_for(path: str) -> Config | None:
    """The reading rule for an MCP client config path (matched case-insensitively, either slash), else None."""
    rooted_path = rooted(path)
    for suffix, (kind, containers) in SUFFIXES.items():
        if rooted_path.endswith("/" + suffix):
            return Config(kind, containers)
    if CLAUDE_SETTINGS.search(rooted_path) and rooted_path.endswith(".json"):
        return Config("json", COMMON, claude=True)
    return None


def is_dedicated(path: str) -> bool:
    """Whether a path is a file that holds only MCP servers (a shell write to it must show its entries)."""
    return any(rooted(path).endswith("/" + name) for name in DEDICATED)


def _claude_switches(value: dict, parsed: Parsed) -> None:
    """`enableAllProjectMcpServers` must be false when present; every `enabledMcpjsonServers` name is an entry to approve."""
    if ENABLE_ALL in value and value[ENABLE_ALL] is not False:
        parsed.problems.append(
            ("enable-all", ENABLE_ALL, f"{ENABLE_ALL} approves every server a project file declares")
        )
    names = value.get(ENABLED, [])
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        parsed.problems.append(("enabled-unreadable", ENABLED, f"{ENABLED} is not a list of server names"))
        return
    parsed.problems += [("enabled", name, f"{ENABLED} approves the server {name!r}") for name in names]


def _hidden(dup: jsonc.Duplicate, config: Config) -> list[tuple[str, object]]:
    """The servers a repeated key hides: every value but the last, which the document itself holds."""
    if dup.path[0] not in config.containers or len(dup.path) > MAX_SERVER_DEPTH:
        return []
    if len(dup.path) == 1:
        return [
            (str(name), entry) for value in dup.values[:-1] if isinstance(value, dict) for name, entry in value.items()
        ]
    return [(str(dup.path[1]), value) for value in dup.values[:-1]]


def read(config: Config, text: str) -> Parsed:
    """The servers and switches a config text holds; ValueError when the text cannot be read as that kind of file."""
    parsed = Parsed()
    if config.kind == "toml":
        document: object = tomllib.loads(text)
    else:
        loaded = jsonc.loads(text)
        document = loaded.value
        for dup in loaded.duplicates:
            digest = hashlib.sha256(json.dumps(dup.values, sort_keys=True, default=str).encode()).hexdigest()[:16]
            where = "/".join(map(str, dup.path))
            parsed.problems.append(
                ("duplicate-key", f"{where}|{digest}", f"repeats the key {where!r}, which clients read differently")
            )
            parsed.servers += _hidden(dup, config)
    if not isinstance(document, dict):
        return parsed
    for key in config.containers:
        block = document.get(key)
        if isinstance(block, dict):
            parsed.servers += [(str(name), entry) for name, entry in block.items()]
    if config.claude:
        _claude_switches(document, parsed)
    return parsed

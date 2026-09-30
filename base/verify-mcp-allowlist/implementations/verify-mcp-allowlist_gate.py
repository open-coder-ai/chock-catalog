#!/usr/bin/env python3
"""Report each server of a written MCP client config that the guard's allowlist does not name.

Runs as the policy's script gate: stdin is {"event", "repo_root", "writes": {path: text}}; exit 0 allows, 1 refuses,
2 is a fault in this check. It prints a findings document, keyed by server name and normalized source, and the
engine runs it again on the baseline text and refuses only the keys the change holds more of, so a server already
there never blocks an unrelated edit, and a renamed or re-argued server is new: the guard judges a name and its
source together. The allowlist is the one in verify-mcp-allowlist.py, read from the file beside this one, never copied.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
JSON_CONFIGS = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    "claude_desktop_config.json",
    ".gemini/settings.json",
)
TOML_CONFIGS = (".codex/config.toml",)
JSON_KEYS = ("mcpServers", "servers")
TOML_KEY = "mcp_servers"


def load_guard():
    """The command guard, whose allowlist and source rule this gate reuses; chock_shellparse sits beside it."""
    sys.path.insert(0, str(HERE))
    try:
        return importlib.import_module("verify-mcp-allowlist")
    finally:
        sys.path.remove(str(HERE))


def config_kind(path: str) -> str | None:
    """'json' or 'toml' when the path is an MCP client config this gate reads, else None."""
    rooted = "/" + path.replace("\\", "/")
    for names, kind in ((JSON_CONFIGS, "json"), (TOML_CONFIGS, "toml")):
        if any(rooted.endswith("/" + name) for name in names):
            return kind
    return None


def servers(kind: str, text: str) -> list[tuple[str, object]]:
    """(name, config) for every server the file declares, one per declaration; ValueError when it cannot be read."""
    if kind == "toml":
        table = tomllib.loads(text).get(TOML_KEY, {})
        return list(table.items()) if isinstance(table, dict) else []
    document = json.loads(text)
    found: list[tuple[str, object]] = []
    for key in JSON_KEYS:
        block = document.get(key) if isinstance(document, dict) else None
        if isinstance(block, dict):
            found.extend((str(name), config) for name, config in block.items())
    return found


def line_of(text: str, needle: str) -> int:
    """The first line naming `needle`, for display; 1 when none does."""
    return next((number for number, line in enumerate(text.splitlines(), 1) if needle in line), 1)


def findings(payload: dict, guard) -> list[dict]:
    """One finding per refused server or unreadable config, naming the file and the server, never its launch line.

    A server's key is its name and its normalized source; an unreadable config's is a digest of its text, so
    any edit to one is new. The engine drops the keys the baseline text held as often.
    """
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        kind = config_kind(path)
        if kind is None:
            continue
        norm = path.replace("\\", "/")
        try:
            written = servers(kind, text)
        except ValueError:
            digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]
            message = f"not parseable as {kind.upper()}, so its MCP servers cannot be verified"
            found.append({"key": f"unreadable|{kind}|{digest}", "path": norm, "line": 1, "message": message})
            continue
        for name, config in written:
            source = guard.source_of(config)
            if why := guard.unlisted([(name, source)]):
                key = f"{name}|{' '.join(source.split())}"
                found.append({"key": key, "path": norm, "line": line_of(text, name), "message": why})
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        found = findings(payload, load_guard())
    except Exception as exc:  # noqa: BLE001 -- a fault must not read as a verdict
        print(f"verify-mcp-allowlist_gate: internal error ({type(exc).__name__}); config not checked", file=sys.stderr)
        return 2
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print("verify-mcp-allowlist: MCP server config refused:", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}: {item['message']}", file=sys.stderr)
    print(
        "Only servers on the allowlist in implementations/verify-mcp-allowlist.py (name + exact command/args/url) may "
        "be configured. Ask a person to review the server and add it there; do not edit the allowlist yourself.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

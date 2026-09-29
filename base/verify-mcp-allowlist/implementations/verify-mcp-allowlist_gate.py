#!/usr/bin/env python3
"""Refuse a written MCP client config that names a server the guard's allowlist does not.

Runs as the policy's script gate: stdin is {"event", "repo_root", "writes": {path: text}}; exit 0 allows, 1 refuses
with the reasons on stderr, 2 is a fault in this check. The allowlist is the one in verify-mcp-allowlist.py, read from
the file beside this one, never copied. At commit only servers the change adds or alters against HEAD are judged, so a
server already committed never blocks an unrelated edit; at tool use every server in the written file is judged.
"""

from __future__ import annotations

import importlib
import json
import subprocess
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
TOOL_USE = "tool_use"


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


def servers(kind: str, text: str) -> dict[str, object]:
    """name -> config for every server the file declares; ValueError when it cannot be read."""
    if kind == "toml":
        table = tomllib.loads(text).get(TOML_KEY, {})
        return dict(table) if isinstance(table, dict) else {}
    document = json.loads(text)
    found: dict[str, object] = {}
    for key in JSON_KEYS:
        block = document.get(key) if isinstance(document, dict) else None
        if isinstance(block, dict):
            found.update({str(name): config for name, config in block.items()})
    return found


def head_text(root: str, path: str) -> str:
    """The file at HEAD; empty when HEAD or the file does not exist."""
    proc = subprocess.run(  # noqa: S603 -- fixed argv, the path is one the runner staged
        ["git", "show", f"HEAD:{path}"],  # noqa: S607
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def entries(guard, kind: str, text: str) -> set[tuple[str, str]]:
    """(name, source) for each server in the text; a text that cannot be read has none."""
    try:
        return {(name, guard.source_of(config)) for name, config in servers(kind, text).items()}
    except ValueError:
        return set()


def findings(payload: dict, guard) -> list[str]:
    """One reason per refused server or unreadable config, naming the file and the server, never its launch line."""
    full = payload.get("event") == TOOL_USE
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        kind = config_kind(path)
        if kind is None:
            continue
        norm = path.replace("\\", "/")
        before = "" if full else head_text(payload["repo_root"], norm)
        if text == before and before:
            continue
        try:
            written = servers(kind, text)
        except ValueError:
            found.append(f"{norm}: not parseable as {kind.upper()}, so its MCP servers cannot be verified")
            continue
        known = entries(guard, kind, before)
        for name, config in written.items():
            source = guard.source_of(config)
            if (name, source) in known:
                continue
            why = guard.unlisted([(name, source)])
            if why:
                found.append(f"{norm}: {why}")
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        found = findings(payload, load_guard())
    except Exception as exc:  # noqa: BLE001 -- a fault must not read as a verdict
        print(f"verify-mcp-allowlist_gate: internal error ({type(exc).__name__}); config not checked", file=sys.stderr)
        return 2
    if not found:
        return 0
    print("verify-mcp-allowlist: MCP server config refused:", file=sys.stderr)
    for item in found:
        print(f"  {item}", file=sys.stderr)
    print(
        "Only servers on the allowlist in implementations/verify-mcp-allowlist.py (name + exact command/args/url) may "
        "be configured. Ask a person to review the server and add it there; do not edit the allowlist yourself.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

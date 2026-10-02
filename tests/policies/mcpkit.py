"""Shared helpers for the verify-mcp-allowlist tests: the shipped scripts loaded in isolation, configs, repos."""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType

from policies import guardkit, scriptkit

POLICY = "verify-mcp-allowlist"
GATE_NAME = "verify-mcp-allowlist_gate"
GATE_FILE = GATE_NAME + ".py"
DIGEST = "sha256:" + "a" * 64
COMMIT = "b" * 40
FS_ARGS = ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/work"]
FS = {"command": "npx", "args": FS_ARGS}
FS_ALLOWED = {"name": "filesystem", "launcher": "npx", "spec": " ".join(FS_ARGS)}
REMOTE_ALLOWED = {"name": "docs", "url_host": "mcp.example.invalid"}
EVIL = {"command": "npx", "args": ["-y", "evil-mcp"]}


def gate() -> ModuleType:
    """The script gate, with the mcpcheck package and chock_scan it ships beside it."""
    return guardkit.load_guard(POLICY, GATE_NAME)


def guard() -> ModuleType:
    """The command guard, resolved the same way."""
    return guardkit.load_guard(POLICY)


def allowlist_text(*servers: dict) -> str:
    return json.dumps({"servers": list(servers)})


def mcp(servers: dict, key: str = "mcpServers") -> str:
    return json.dumps({key: servers})


def repo_with(tmp_path: Path, *, head: dict[str, str] | None = None, disk: dict[str, str] | None = None) -> Path:
    """A git repo whose HEAD holds `head` and whose work tree then gets `disk` written over it."""
    repo = scriptkit.init_repo(tmp_path / "repo", {"README.md": "x\n", **(head or {})})
    scriptkit.write(repo, disk or {})
    return repo

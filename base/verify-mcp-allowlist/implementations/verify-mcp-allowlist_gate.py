#!/usr/bin/env python3
"""Report each MCP server entry, enable switch or allowlist change in a written config that the policy refuses.

Runs as the policy's script gate: stdin is {"event", "repo_root", "writes": {path: text}}; exit 0 allows, 1 refuses,
2 is a fault in this check. It prints a findings document keyed by rule, server name and a digest of the entry, and
the engine runs it again on the baseline text and refuses only the keys the change holds more of: a server already
there never blocks an unrelated edit, and a renamed or re-argued one is new. The allowlist is `.chock/mcp-allowlist.json`.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from mcpcheck import allowlist, configs, entry, rules

#: Finding rules that refuse (exit 1): the v1 tiers (an unlisted or altered server, an unreadable config) and the
#: allowlist's own integrity. Every other rule is new in v2 and exits 4, a warning, while it is observed (decision D15);
#: promoting one is adding it here.
ENFORCED = rules.ENFORCED | {"allowlist-entry", "allowlist-unreadable", "unreadable", "unreadable-entry"}
WARN_EXIT = 4
FOOTER = (
    f"Only servers on the allowlist ({allowlist.PATH}: name with launcher and exact arguments, or url host) that also "
    "pass the pin, shell, https, credential and option rules may be configured. Ask a person to review the server and "
    "edit the allowlist from their own shell; do not edit it yourself."
)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def line_of(text: str, needle: str) -> int:
    """The first line naming `needle`, for display; 1 when none does."""
    return next((number for number, line in enumerate(text.splitlines(), 1) if needle in line), 1)


def is_allowlist(path: str) -> bool:
    return configs.rooted(path).endswith("/" + allowlist.PATH)


def item(path: str, text: str, needle: str, key: str, message: str) -> dict:
    return {"key": key, "path": path.replace("\\", "/"), "line": line_of(text, needle), "message": message}


def server_findings(path: str, text: str, name: str, raw: object, allowed: tuple[allowlist.Allowed, ...]) -> list[dict]:
    """One finding per rule a server entry breaks; an entry that is not a readable server is itself a finding."""
    try:
        server = entry.from_config(name, raw)
    except entry.EntryError as exc:
        key = f"unreadable-entry|{name}|{digest(json.dumps(raw, sort_keys=True, default=str))}"
        return [item(path, text, name, key, f"server {name!r}: {exc}, so it cannot be verified")]
    return [
        item(path, text, name, f"{rule}|{name}|{server.digest()}", f"server {name!r}: {message}")
        for rule, message in rules.judge(server, allowed)
    ]


def config_findings(path: str, text: str, config: configs.Config, allowed: tuple[allowlist.Allowed, ...]) -> list[dict]:
    try:
        parsed = configs.read(config, text)
    except (ValueError, RecursionError):
        message = f"not parseable as {config.kind.upper()}, so its MCP servers cannot be verified"
        return [item(path, text, "", f"unreadable|{config.kind}|{digest(text)}", message)]
    names = {entry.name for entry in allowed}
    found = [
        item(path, text, key.partition("|")[0], f"{rule}|{key}", message)
        for rule, key, message in parsed.problems
        if not (rule == "enabled" and key in names)
    ]
    for name, raw in parsed.servers:
        found += server_findings(path, text, name, raw, allowed)
    return found


def allowlist_findings(path: str, text: str) -> list[dict]:
    """A write of the allowlist at an agent event: every entry it holds is new unless the baseline held it too."""
    try:
        entries = allowlist.parse(text)
    except allowlist.AllowlistError as exc:
        return [item(path, text, "", f"allowlist-unreadable|{digest(text)}", f"the MCP allowlist is {exc}")]
    return [
        item(
            path,
            text,
            f'"{one.name}"',
            f"allowlist-entry|{one.name}|{one.launcher}|{one.spec}|{one.host.host.name if one.host else ''}",
            f"the allowlist entry {one.name!r} was added or changed; only a person approves an MCP server",
        )
        for one in entries
    ]


def findings(payload: dict) -> list[dict]:
    """Every refused item in the written files; a config is judged against the allowlist that applies to the event."""
    event, writes = str(payload.get("event", "")), payload.get("writes", {})
    repo = Path(payload.get("repo_root") or ".")
    watched = {path: configs.config_for(path) for path in writes if not is_allowlist(path)}
    found: list[dict] = []
    allowed: tuple[allowlist.Allowed, ...] = ()
    if any(watched.values()):
        try:
            allowed, _ = allowlist.load(repo, event)
        except allowlist.AllowlistError as exc:
            found.append(item(allowlist.PATH, "", "", f"allowlist-unreadable|{exc}", f"the MCP allowlist is {exc}"))
    for path, text in sorted(writes.items()):
        if is_allowlist(path):
            found += allowlist_findings(path, text) if event in allowlist.AGENT_EVENTS else []
        elif watched[path] is not None:
            found += config_findings(path, text, watched[path], allowed)
    return found


def main() -> int:
    try:
        found = findings(json.load(sys.stdin))
    except Exception as exc:  # noqa: BLE001 -- a fault must not read as a verdict
        print(f"verify-mcp-allowlist_gate: internal error ({type(exc).__name__}); config not checked", file=sys.stderr)
        return 2
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    refusing = any(one["key"].split("|", 1)[0] in ENFORCED for one in found)
    print(
        "verify-mcp-allowlist: MCP server config refused:"
        if refusing
        else "verify-mcp-allowlist: MCP server config findings (observed, not yet refusing):",
        file=sys.stderr,
    )
    for one in found:
        print(f"  {one['path']}: {one['message']}", file=sys.stderr)
    print(FOOTER, file=sys.stderr)
    return 1 if refusing else WARN_EXIT


if __name__ == "__main__":
    sys.exit(main())

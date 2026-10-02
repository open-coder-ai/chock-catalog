"""Load the agent-permissions-scan gate against its shipped chock_scan copy; tests/chock_scan shares the package name."""

from __future__ import annotations

import sys
from pathlib import Path

from policies import scriptkit

POLICY, NAME = "agent-permissions-scan", "agent-permissions-scan.py"
__all__ = ["CLAUDE", "NAME", "POLICY", "keys", "load", "mod", "payload", "rules", "sidecar", "walk"]


def _owned(name: str) -> bool:
    return name == "chock_scan" or name.startswith("chock_scan.")


def _load_isolated() -> object:
    """Whichever package loads first, each keeps its own modules: the gate's are bound at import, then restored."""
    saved = {name: sys.modules.pop(name) for name in list(sys.modules) if _owned(name)}
    path = list(sys.path)
    try:
        return scriptkit.load(POLICY, NAME)
    finally:
        for name in [name for name in sys.modules if _owned(name)]:
            del sys.modules[name]
        sys.modules.update(saved)
        sys.path[:] = path


mod = _load_isolated()
load, rules, sidecar, walk = (sys.modules[f"perms.{name}"] for name in ("load", "rules", "sidecar", "walk"))
CLAUDE = ".claude/settings.json"


def payload(repo: Path, writes: dict[str, str], event: str = "commit", **extra: object) -> dict:
    return {"event": event, "repo_root": str(repo), "writes": writes, **extra}


def keys(repo: Path, writes: dict[str, str], event: str = "commit", **extra: object) -> list[str]:
    return [f["key"] for f in mod.findings(payload(repo, writes, event, **extra))]

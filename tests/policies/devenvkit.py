"""Drive the agent-devenv-autoexec gate in-process: (rule, severity) pairs for a write."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from policies import scriptkit

POLICY, SCRIPT = "agent-devenv-autoexec", "agent-devenv-autoexec-gate.py"


def _owned(name: str) -> bool:
    return name == "chock_scan" or name.startswith("chock_scan.")


def _load_isolated() -> object:
    """Load the gate against its shipped chock_scan copy; tests/chock_scan shares the package name.

    Whichever loads first, each keeps its own modules: the gate's are bound at import, then the
    test package's entries and sys.path are put back.
    """
    saved = {name: sys.modules.pop(name) for name in list(sys.modules) if _owned(name)}
    path = list(sys.path)
    try:
        return scriptkit.load(POLICY, SCRIPT)
    finally:
        for name in [name for name in sys.modules if _owned(name)]:
            del sys.modules[name]
        sys.modules.update(saved)
        sys.path[:] = path


gate = _load_isolated()


def found(writes: dict[str, str], event: str = "commit", root: Path | None = None, **extra: object) -> list[dict]:
    return gate.findings({"event": event, "repo_root": str(root or Path.cwd()), "writes": writes, **extra})


def rules(path: str, text: str, event: str = "commit", root: Path | None = None) -> list[tuple[str, str]]:
    """Each finding's (rule, severity) for one written file."""
    return [(f["rule"], f["severity"]) for f in found({path: text}, event, root)]


def keys(path: str, text: str) -> list[str]:
    return [f["key"] for f in found({path: text})]


def as_json(value: object) -> str:
    return json.dumps(value)

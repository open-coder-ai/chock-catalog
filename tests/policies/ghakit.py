"""Load ci-github-actions-security's gate and rule modules in-process, and run them on YAML text.

tests/ is on the path and holds a `chock_scan` test package, so the policy's shipped copy is
imported with sys.modules and sys.path swapped for the duration, then both are put back.
"""

from __future__ import annotations

import sys
from types import ModuleType

from policies import scriptkit

POLICY = "ci-github-actions-security"
GATE = "ci-github-actions-security-gate.py"
IMPL = str(scriptkit.script_path(POLICY, GATE).parent)
OWNED = ("chock_scan", "ghascan")


def _ours(name: str) -> bool:
    return any(name == root or name.startswith(root + ".") for root in OWNED)


def _load() -> tuple[ModuleType, dict[str, ModuleType]]:
    saved = {k: sys.modules.pop(k) for k in list(sys.modules) if _ours(k)}
    path = list(sys.path)
    try:
        gate = scriptkit.load(POLICY, GATE)
        mods = {k: sys.modules[k] for k in list(sys.modules) if _ours(k)}
    finally:
        for k in [k for k in sys.modules if _ours(k)]:
            del sys.modules[k]
        sys.modules.update(saved)
        sys.path[:] = path
    return gate, mods


gate, MODULES = _load()
expr = MODULES["ghascan.expr"]
tree = MODULES["ghascan.tree"]
model = MODULES["ghascan.model"]
rules = MODULES["ghascan.rules"]
TABLES = gate.load_tables()

WF = ".github/workflows/ci.yml"


def found(text: str, path: str = WF, event: str = "tool_use") -> list[dict]:
    return gate.findings({"event": event, "writes": {path: text}}, TABLES)


def rule_ids(text: str, path: str = WF) -> list[str]:
    return [f["rule"] for f in found(text, path)]


def of(rule: str, text: str, path: str = WF) -> list[dict]:
    return [f for f in found(text, path) if f["rule"] == rule]


def workflow(on: str, steps: str, *, top: str = "permissions: {}\n", job: str = "") -> str:
    """A one-job workflow: `on` is the trigger block body, `steps` the step list, indented by the caller."""
    return f"on:\n{on}\n{top}jobs:\n  build:\n    runs-on: ubuntu-latest\n{job}    steps:\n{steps}"

"""Load the dockerfile-compose-security gate with the chock_scan copy it ships.

tests/ is on pytest's pythonpath and tests/chock_scan is a package of the same name, so a plain
import would resolve the gate's `from chock_scan import yamlpath` to the test package. The gate's
own copy is imported with that entry set aside, then the entry is put back so the chock_scan tests
still import as before.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType

import pytest
from policies import scriptkit

POLICY, SCRIPT = "dockerfile-compose-security", "dockerfile-compose-security-gate.py"


def load() -> ModuleType:
    if "dkscan.composeyaml" in sys.modules:
        return scriptkit.load(POLICY, SCRIPT)
    held = {name: sys.modules.pop(name) for name in list(sys.modules) if name.split(".")[0] == "chock_scan"}
    try:
        return scriptkit.load(POLICY, SCRIPT)
    finally:
        for name in [n for n in sys.modules if n.split(".")[0] == "chock_scan"]:
            del sys.modules[name]
        sys.modules.update(held)


#: A repository root with no .chock/compiled: no sibling gate is installed, so nothing is deferred.
BARE = str(Path(__file__).resolve().parent)
FETCH_EXEC, PINS, AGENTIC = "block-fetch-exec-in-files", "block-unpinned-agent-components", "agentic-code-security"


def installed(root: Path, *policies: str) -> str:
    """`root` as a repository where `policies` are installed (their .chock/compiled folders exist)."""
    for policy in policies:
        (root / ".chock" / "compiled" / policy).mkdir(parents=True, exist_ok=True)
    return str(root)


@pytest.fixture
def person(monkeypatch: pytest.MonkeyPatch) -> None:
    """A person's shell: none of the variables the engine reads as an agent's commit."""
    for name in ("CHOCK_AGENT_COMMIT", "CLAUDECODE", "AI_AGENT"):
        monkeypatch.delenv(name, raising=False)

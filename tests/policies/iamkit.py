"""Drive the iam-policy-scan gate in-process: the findings of a write, and the gate's own exit code."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest
from policies import scriptkit
from trees import ROOT

POLICY = "iam-policy-scan"
IMPL = ROOT / "agentic-security" / POLICY / "implementations"


def _owned(name: str) -> bool:
    return name == "chock_scan" or name.startswith("chock_scan.")


def _load_isolated() -> object:
    """Load the gate against its shipped chock_scan copy; tests/chock_scan shares the package name.

    The gate's modules are bound at import, then the test package's entries and sys.path are put back.
    """
    saved = {name: sys.modules.pop(name) for name in list(sys.modules) if _owned(name)}
    path = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location("iam_policy_scan_gate", IMPL / "iam-policy-scan-gate.py")
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name in [name for name in sys.modules if _owned(name)]:
            del sys.modules[name]
        sys.modules.update(saved)
        sys.path[:] = path


gate = _load_isolated()


def payload(writes: dict[str, str], event: str = "commit", root: Path | None = None) -> dict:
    return {"event": event, "repo_root": str(root or IMPL), "writes": writes}


def found(writes: dict[str, str], event: str = "commit", root: Path | None = None) -> list:
    return gate.judged(payload(writes, event, root))


def rules(path: str, text: str, event: str = "commit", root: Path | None = None) -> list[tuple[str, str]]:
    """Each finding's (rule, tier) for one written file, in the order found."""
    return [(f.rule, f.tier) for f in found({path: text}, event, root)]


def run_main(monkeypatch: pytest.MonkeyPatch, data: dict) -> tuple[int, dict | None, str]:
    """(exit code, findings document or None, stderr) of the gate's main() for one payload."""
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(data)))
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    code = gate.main()
    return code, (json.loads(out.getvalue()) if out.getvalue() else None), err.getvalue()


def repo_with(tmp_path: Path, head: dict[str, str]) -> Path:
    """A git repository whose HEAD holds `head`."""
    return scriptkit.init_repo(tmp_path / "r", head or {"README.txt": "base\n"})


def doc(*statements: dict) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)}, indent=2) + "\n"


ADMIN = {"Effect": "Allow", "Action": ["*"], "Resource": "*"}

"""Shared loaders and lockfile builders for the lockfile-integrity tests."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType

from policies import scriptkit

POLICY = "lockfile-integrity"
NAME = "lockfile-integrity-gate.py"


def _load() -> tuple[ModuleType, dict[str, ModuleType]]:
    """The gate and its lockscan modules, bound to the chock_scan copy the policy ships.

    Loading the gate puts its implementations folder on sys.path, as the runner does; under pytest the name
    chock_scan may already mean tests/chock_scan, so it is set aside while the shipped copy is imported.
    """
    saved = {k: sys.modules.pop(k) for k in list(sys.modules) if k == "chock_scan" or k.startswith("chock_scan.")}
    try:
        loaded = scriptkit.load(POLICY, NAME)
        names = ("model", "sources", "npm", "yarn", "pnpm", "python", "other", "rules", "sync")
        return loaded, {name: importlib.import_module(f"lockscan.{name}") for name in names}
    finally:
        for key in [k for k in sys.modules if k == "chock_scan" or k.startswith("chock_scan.")]:
            del sys.modules[key]
        sys.modules.update(saved)
        here = str(scriptkit.script_path(POLICY, NAME).resolve().parent)
        sys.path[:] = [p for p in sys.path if p != here]


gate, _modules = _load()
model = _modules["model"]
sources = _modules["sources"]
npm = _modules["npm"]
yarn = _modules["yarn"]
pnpm = _modules["pnpm"]
python = _modules["python"]
other = _modules["other"]
rules = _modules["rules"]
sync = _modules["sync"]
SHA40 = "a" * 40


def h(c: str = "A") -> str:
    """A well-formed sha512 integrity string."""
    return "sha512-" + c * 86 + "=="


def reg(name: str, ver: str) -> str:
    return f"https://registry.npmjs.org/{name}/-/{name}-{ver}.tgz"


def pkg(name: str, ver: str, c: str = "A", resolved: str | None = None, integrity: object = True, **extra) -> dict:
    fields: dict = {"version": ver, "resolved": resolved or reg(name, ver)}
    if integrity is not False:
        fields["integrity"] = h(c) if integrity is True else integrity
    fields.update(extra)
    return fields


def npm_lock(pkgs: dict[str, dict], direct: tuple[str, ...] = ("left-pad",)) -> str:
    packages: dict = {"": {"name": "app", "dependencies": {d: "^1.0.0" for d in direct}}}
    packages.update({f"node_modules/{name}": fields for name, fields in pkgs.items()})
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages}, indent=2) + "\n"


def manifest(deps: dict[str, str], **extra) -> str:
    return json.dumps({"name": "app", "version": "1.0.0", "dependencies": deps, **extra}, indent=2) + "\n"


BASE_LOCK = npm_lock({"left-pad": pkg("left-pad", "1.3.0")})
BASE_MANIFEST = manifest({"left-pad": "^1.3.0"})


def rules_of(path: str, text: str, allow: tuple = (), note: str = "") -> list[str]:
    """The rule ids the per-file rules report for one lock."""
    entries, refusal = rules.read(path, text)
    if refusal:
        return [refusal.rule]
    return [f.rule for f in rules.state_findings(path, entries, allow, note)]


def payload(repo: Path, writes: dict[str, str], event: str = "commit", **extra) -> dict:
    return {"event": event, "repo_root": str(repo), "writes": writes, **extra}


def found(repo: Path, writes: dict[str, str], event: str = "commit", **extra) -> list[str]:
    findings, _ = gate.judge(payload(repo, writes, event, **extra))
    return sorted(f.rule for f in findings)

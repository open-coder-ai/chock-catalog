"""Load opaque-blob-guard's gate in-process, beside its own copies of `chock_scan` and `blobguard`."""

from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path
from types import ModuleType, SimpleNamespace

from policies import scriptkit

POLICY = "opaque-blob-guard"
NAME = "opaque-blob-guard-gate.py"
PACKAGES = ("chock_scan", "blobguard")


def _ours(name: str) -> bool:
    return any(name == p or name.startswith(p + ".") for p in PACKAGES)


def load() -> tuple[ModuleType, SimpleNamespace]:
    """The gate module and its submodules (`source`, `allow`, `detect`, `judge`, `tables`, `gradle`).

    sys.path and sys.modules are left as found, so the repo-level `tests/chock_scan` package stays intact.
    """
    path, saved = list(sys.path), {k: v for k, v in sys.modules.items() if _ours(k)}
    for name in saved:
        del sys.modules[name]
    try:
        gate = scriptkit.load(POLICY, NAME)
        loaded = {k.removeprefix("blobguard."): v for k, v in sys.modules.items() if k.startswith("blobguard.")}
        return gate, SimpleNamespace(**loaded)
    finally:
        for name in [k for k in sys.modules if _ours(k)]:
            del sys.modules[name]
        sys.modules.update(saved)
        sys.path[:] = path


def make_repo(tmp_path: Path, files: dict[str, str | bytes], head: dict[str, str | bytes] | None = None) -> Path:
    """A repository whose HEAD holds `head` (or a README) and whose index and working tree also hold `files`."""
    repo = scriptkit.init_repo(tmp_path / "r", head if head is not None else {"README.md": "x\n"})
    scriptkit.write(repo, files)
    scriptkit.git(repo, "add", "-A")
    return repo


def run(
    gate: ModuleType, repo: Path, paths: Iterable[str], event: str = "commit", writes: dict[str, str] | None = None
) -> list[dict]:
    """The gate's findings for `paths` (the engine hands text writes; the gate reads bytes itself)."""
    body = {p: "" for p in paths} if writes is None else writes
    return gate.findings({"event": event, "repo_root": str(repo), "writes": body})


def rules(found: list[dict]) -> list[tuple[str, str]]:
    return [(f["path"], f["rule"]) for f in found]

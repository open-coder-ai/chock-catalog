"""The person-only sidecar `.chock/credential-allowlist.json`, read from HEAD: a closed schema of identity names."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

PATH = ".chock/credential-allowlist.json"
PROVIDERS = frozenset(("aws", "gcloud", "azure", "kubernetes"))

Allowlist = dict[str, frozenset[str]]


class SidecarError(ValueError):
    """The sidecar is not the closed schema, so none of it is honoured."""


def committed(root: Path) -> str | None:
    """The sidecar's text at HEAD, or None when HEAD has none or git cannot say; the worktree copy never counts."""
    try:
        proc = subprocess.run(  # noqa: S603 -- a fixed git argv; the path is an argument, never a shell word
            ["git", "show", f"HEAD:{PATH}"],  # noqa: S607 -- git from PATH, as the runner's own
            cwd=root,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else None


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        msg = "a repeated key"
        raise SidecarError(msg)
    return dict(pairs)


def parse(text: str) -> Allowlist:
    """{provider: names}; SidecarError on any text that breaks the closed schema."""
    try:
        document = json.loads(text, object_pairs_hook=_unique)
    except ValueError as exc:
        raise SidecarError(str(exc)) from None
    if not isinstance(document, dict) or not set(document) <= PROVIDERS:
        msg = f"not an object with only the keys {', '.join(sorted(PROVIDERS))}"
        raise SidecarError(msg)
    out = {}
    for provider, names in document.items():
        if not isinstance(names, list) or not all(isinstance(n, str) and n.strip() for n in names):
            msg = f"`{provider}` is not a list of names"
            raise SidecarError(msg)
        out[provider] = frozenset(names)
    return out


def load(root: Path) -> tuple[Allowlist, str]:
    """The committed allowlist and, when the sidecar is there but broken, why none of it counts."""
    text = committed(root)
    if text is None:
        return {}, ""
    try:
        return parse(text), ""
    except SidecarError as exc:
        return {}, f"{PATH} in HEAD is not honoured ({exc})"

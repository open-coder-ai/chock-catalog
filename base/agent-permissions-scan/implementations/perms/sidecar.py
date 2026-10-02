"""The waiver sidecar `.chock/devenv.json`: a closed schema, read from HEAD in the agent and from the change for a person."""

from __future__ import annotations

import subprocess
from pathlib import Path

from chock_scan import jsonc

PATH = ".chock/devenv.json"
KEYS = frozenset({"waive"})
WAIVER_KEYS = frozenset({"file", "path", "value"})

Waiver = tuple[str, str, str]


class SidecarError(ValueError):
    """The sidecar is not the closed schema, so none of it is honoured."""


def committed(root: Path, path: str) -> str | None:
    """The text of `path` at HEAD, or None when HEAD has no such file or git cannot say."""
    try:
        proc = subprocess.run(  # noqa: S603 -- a fixed git argv; the path is an argument, never a shell word
            ["git", "show", f"HEAD:./{path}"],  # noqa: S607 -- git from PATH, as the runner's own
            cwd=root,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    return proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else None


def waivers(text: str) -> frozenset[Waiver]:
    """The (file, path, value) waivers of a sidecar; SidecarError on any text that breaks the closed schema."""
    try:
        document = jsonc.loads(text)
    except jsonc.JsoncError as exc:
        raise SidecarError(str(exc)) from None
    value = document.value
    if document.duplicates or not isinstance(value, dict) or not set(value) <= KEYS:
        msg = "not an object with only the key `waive`, or a repeated key"
        raise SidecarError(msg)
    listed = value.get("waive", [])
    if not isinstance(listed, list):
        msg = "`waive` is not a list"
        raise SidecarError(msg)
    out = set()
    for item in listed:
        if not isinstance(item, dict) or set(item) != WAIVER_KEYS or not all(isinstance(v, str) for v in item.values()):
            msg = "a waiver is not exactly {file, path, value}, all text"
            raise SidecarError(msg)
        out.add((item["file"].replace("\\", "/").removeprefix("./"), item["path"], item["value"]))
    return frozenset(out)


def committed_all(root: Path, path: str) -> list[str]:
    """The HEAD text of every tracked file whose path equals `path` ignoring case (file systems may fold it)."""
    try:
        proc = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "-z", "HEAD"],  # noqa: S607 -- git from PATH, as the runner's own
            cwd=root,
            capture_output=True,
            check=False,
        )
    except OSError:
        return []
    names = proc.stdout.decode("utf-8", "replace").split("\0") if proc.returncode == 0 else []
    wanted = path.casefold()
    return [text for name in names if name.casefold() == wanted and (text := committed(root, name)) is not None]

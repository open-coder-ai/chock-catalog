"""A Claude Code plugin's own hooks folder: the module a loaded mod runs sits there (stdlib only)."""

from __future__ import annotations

import os

MANIFEST = ".claude-plugin"  # the folder that makes a directory a plugin root


def repo_root() -> str:
    """The repository folder the guard runs in: the nearest folder holding `.git`, from the hook's own working folder."""
    start = os.path.abspath(os.environ.get("CHOCK_HOOK_CWD") or os.getcwd())
    folder = start
    while not os.path.exists(os.path.join(folder, ".git")):
        parent = os.path.dirname(folder)
        if parent == folder:
            return start
        folder = parent
    return folder


def _entry(folder: str, name: str) -> str | None:
    """The entry of a folder spelled `name` in any case (a path is matched lowercase; a filesystem may not be)."""
    try:
        return next((e for e in os.listdir(folder) if e.lower() == name), None)
    except OSError:
        return None


def _plugin_root(folder: str) -> bool:
    """Whether a folder holds `.claude-plugin/`."""
    found = _entry(folder, MANIFEST)
    return found is not None and os.path.isdir(os.path.join(folder, found))


def plugin_hooks(normal: str, base: str | None = None) -> bool:
    """Whether a normalised path lies in a `hooks` folder that sits directly in a plugin root.

    `hooks` anywhere else (`src/hooks/useThing.ts`) is an ordinary folder. The folders on the way are looked up on disk, from `base`.
    """
    parts = normal.split("/")
    if "hooks" not in parts:
        return False
    folder = "/" if normal.startswith("/") else base or repo_root()
    for part in (p for p in parts if p not in ("", ".")):
        if part == "hooks" and _plugin_root(folder):
            return True
        found = _entry(folder, part)
        if found is None:
            return False
        folder = os.path.join(folder, found)
    return False

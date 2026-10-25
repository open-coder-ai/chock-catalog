"""The folder git runs hooks from when `core.hooksPath` moves it off `.git/hooks`: chock installs its dispatchers there (stdlib only)."""

from __future__ import annotations

import os
import re
from functools import lru_cache

from pathplugin import repo_root

_SECTION = re.compile(r"\s*\[\s*([^\s\]\"]+)\s*\]")  # `[core]`; `[core "x"]` is a subsection and does not match
_KEY = re.compile(r"\s*hookspath\s*=\s*(.*)", re.IGNORECASE)


def _configs(base: str) -> list[str]:
    """The git config files that can set the key: the repository's, the user's two, the system's."""
    home = os.path.expanduser("~")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return [
        os.path.join(base, ".git", "config"),
        os.path.join(home, ".gitconfig"),
        os.path.join(xdg, "git", "config"),
        "/etc/gitconfig",
    ]


def _value(raw: str) -> str:
    """A config value as git reads it: a trailing comment dropped, one pair of quotes removed."""
    text = re.sub(r"\s+[#;].*$", "", raw).strip()
    return text[1:-1] if len(text) > 1 and text[0] == text[-1] == '"' else text


def _read(config: str) -> list[str]:
    """Every `core.hooksPath` value one config file holds; a file that cannot be read holds none."""
    try:
        with open(config, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    found, core = [], False
    for line in lines:
        if section := _SECTION.match(line):
            core = section[1].lower() == "core"
        elif core and (key := _KEY.match(line)):
            found.append(_value(key[1]))
    return found


@lru_cache(maxsize=4)  # one hook process judges thousands of paths against the same config
def _folders(base: str) -> tuple[str, ...]:
    values = (value for config in _configs(base) for value in _read(config))
    folders = (value.replace("\\", "/").rstrip("/").lower() for value in values)
    return tuple(folder for folder in folders if folder not in ("", "."))


def hooks_folders(base: str | None = None) -> tuple[str, ...]:
    """The `core.hooksPath` values set for the repository at `base`, as lowercase slash paths, none that names the whole tree."""
    return _folders(base or repo_root())


def in_hooks_folder(normal: str, base: str | None = None) -> bool:
    """Whether a normalised path is a configured hooks folder or lies in one; a relative folder matches at any depth, as the folders list does."""
    return any(
        normal == folder or normal.startswith(f"{folder}/")
        if folder.startswith("/")
        else f"/{normal}/".find(f"/{folder}/") >= 0
        for folder in hooks_folders(base)
    )

"""Gradle build scripts and version catalogs: dependency coordinates and versioned plugin ids, by regex and tomllib."""

from __future__ import annotations

import re
import tomllib

_COORD = re.compile(r"""['"]([\w\-]+(?:\.[\w\-]+)+):([\w.\-]+)(?::[^'"\s]*)?['"]""")
_ID = r"""['"]([\w.\-]+)['"]"""
_MAP = re.compile(rf"group\s*[:=]\s*{_ID}\s*,\s*name\s*[:=]\s*{_ID}|name\s*[:=]\s*{_ID}\s*,\s*group\s*[:=]\s*{_ID}")
_PLUGIN = re.compile(r"""\bid\s*\(?\s*['"]([\w\-]+(?:\.[\w\-]+)+)['"]\s*\)?\s*version\b""")
_KOTLIN = re.compile(r"""\bkotlin\s*\(\s*['"]([\w\-]+)['"]\s*\)\s*version\b""")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def gradle_names(text: str) -> list[str]:
    """`group:artifact` for every quoted coordinate with a dotted group, map notation in either order, and
    `plugin:<id>` for versioned plugins.

    Any configuration, call form or line layout is read because the coordinate string is what is matched. Plugins
    without a version are the ones Gradle ships, so they are not packages. Computed coordinates are not read.
    """
    body = _BLOCK_COMMENT.sub("", text.removeprefix("\ufeff"))
    code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("//"))
    names = [f"{g}:{a}" for g, a in _COORD.findall(code)]
    for g1, n1, n2, g2 in _MAP.findall(code):
        names.append(f"{g1 or g2}:{n1 or n2}")
    names += [f"plugin:{plugin}" for plugin in _PLUGIN.findall(code)]
    return names + [f"plugin:org.jetbrains.kotlin.{short}" for short in _KOTLIN.findall(code)]


def _library(entry: object) -> str | None:
    if isinstance(entry, str):
        parts = entry.split(":")
        return ":".join(parts[:2]) if len(parts) > 1 else None
    if isinstance(entry, dict):
        module = entry.get("module")
        if isinstance(module, str):
            return module
        if isinstance(entry.get("group"), str) and isinstance(entry.get("name"), str):
            return f"{entry['group']}:{entry['name']}"
    return None


def version_catalog_names(text: str) -> list[str]:
    """Libraries and plugins of a libs.versions.toml, in the same spelling gradle_names reports."""
    data = tomllib.loads(text.removeprefix("\ufeff"))
    libraries = data.get("libraries")
    plugins = data.get("plugins")
    names = [n for entry in (libraries.values() if isinstance(libraries, dict) else []) if (n := _library(entry))]
    for entry in plugins.values() if isinstance(plugins, dict) else []:
        ident = entry.get("id") if isinstance(entry, dict) else entry.split(":")[0] if isinstance(entry, str) else None
        if isinstance(ident, str):
            names.append(f"plugin:{ident}")
    return names

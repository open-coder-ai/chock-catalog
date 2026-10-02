"""Gradle build scripts and version catalogs: dependency coordinates and versioned plugin ids, by regex and tomllib."""

from __future__ import annotations

import re
import tomllib

_VERSIONED = re.compile(r"""['"]([\w\-]+(?:\.[\w\-]+)*):([\w.\-]+):[^'"\s]+['"]""")
_KEYWORDED = re.compile(
    r"""\b(?:\w*(?:mplementation|Only|lasspath|ompile|untime|rocessor|Api|Desugaring|Checks|Util|Plugins)"""
    r"""|api|kapt|ksp|provided|optional|shadow)\b"""
    r"""\s*(?:\(\s*)?(?:(?:enforcedPlatform|platform)\s*\(\s*)?['"]([\w\-]+(?:\.[\w\-]+)*):([\w.\-]+)(?::[^'"\s]*)?['"]"""
)
_CONTINUED = re.compile(r",[ \t]*\n[ \t]*")
_ID = r"""['"]([\w.\-]+)['"]"""
_GROUP = re.compile(rf"\bgroup\s*[:=]\s*{_ID}")
_NAME = re.compile(rf"\bname\s*[:=]\s*{_ID}")
_PLUGIN = re.compile(r"""\bid\s*\(?\s*['"]([\w\-]+(?:\.[\w\-]+)+)['"]\s*\)?\s*version\b""")
_KOTLIN = re.compile(r"""\bkotlin\s*\(\s*['"]([\w\-]+)['"]\s*\)\s*version\b""")


def gradle_names(text: str) -> list[str]:
    """`group:artifact` from a quoted coordinate with a version, one on a dependency configuration without, map
    notation in any order on a line, and `plugin:<id>` for versioned plugins.

    No comment is stripped (a glob such as `**/*.class` would open a fake block comment, and a `//` line can end one),
    so a commented-out dependency is reported too, and the baseline absorbs one that was already there. Plugins
    without a version are the ones Gradle ships. Computed coordinates are not read.
    """
    code = _CONTINUED.sub(", ", text.removeprefix("\ufeff"))
    names = [f"{g}:{a}" for g, a in _VERSIONED.findall(code) + _KEYWORDED.findall(code)]
    for line in code.splitlines():
        group, name = _GROUP.search(line), _NAME.search(line)
        if group and name:
            names.append(f"{group.group(1)}:{name.group(1)}")
    names += [f"plugin:{plugin}" for plugin in _PLUGIN.findall(code)]
    names += [f"plugin:org.jetbrains.kotlin.{short}" for short in _KOTLIN.findall(code)]
    return list(dict.fromkeys(names))


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

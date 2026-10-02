"""Gradle build scripts and version catalogs: dependency coordinates and versioned plugin ids, by regex and tomllib."""

from __future__ import annotations

import re
import tomllib

_CONFIG = (
    r"(?:\w*(?:Implementation|Api|CompileOnly|RuntimeOnly|AnnotationProcessor|Classpath|Compile|Runtime|Kapt|Ksp)"
    r"|implementation|api|compileOnly|runtimeOnly|annotationProcessor|classpath|compile|runtime|provided|kapt|ksp)"
)
_STRING = re.compile(
    rf"""\b{_CONFIG}\b\s*\(?\s*(?:(?:platform|enforcedPlatform)\s*\(\s*)?['"]([\w.\-]+):([\w.\-]+)(?::[^'"]*)?['"]"""
)
_MAP = re.compile(r"""group\s*[:=]\s*['"]([\w.\-]+)['"]\s*,\s*name\s*[:=]\s*['"]([\w.\-]+)['"]""")
_PLUGIN = re.compile(r"""\bid\s*\(?\s*['"]([\w\-]+(?:\.[\w\-]+)+)['"]\s*\)?\s*version\b""")


def gradle_names(text: str) -> list[str]:
    """`group:artifact` from string and map notation on dependency configurations; `plugin:<id>` for versioned plugins.

    Plugins without a version are the ones Gradle ships, so they are not packages. Computed coordinates are not read.
    """
    names: list[str] = []
    for line in text.removeprefix("\ufeff").splitlines():
        if line.lstrip().startswith("//"):
            continue
        names += [f"{g}:{a}" for g, a in _STRING.findall(line) + _MAP.findall(line)]
        names += [f"plugin:{plugin}" for plugin in _PLUGIN.findall(line)]
    return names


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

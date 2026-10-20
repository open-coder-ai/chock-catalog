"""package.json: dependency tables, npm aliases, overrides, resolutions and catalogs. Names only."""

from __future__ import annotations

import json

_TABLES = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_BUNDLED = ("bundledDependencies", "bundleDependencies")


def strip_range(spec: str) -> str:
    """`name@^1` -> `name`, `@scope/name@1` -> `@scope/name`."""
    at = spec.find("@", 1)
    return spec if at < 0 else spec[:at]


def _alias(spec: object) -> list[str]:
    """The package an `npm:` alias installs: the alias key is a name only locally."""
    if isinstance(spec, str) and spec.startswith("npm:"):
        return [strip_range(spec[4:])]
    return []


_LOCAL = ("workspace:", "file:", "link:", "portal:")


def _table(value: object) -> list[str]:
    """Keys of a name -> spec table, plus the real package behind every npm alias; local specs are not packages."""
    if not isinstance(value, dict):
        return []
    return [
        name
        for key, spec in value.items()
        if not (isinstance(spec, str) and spec.startswith(_LOCAL))
        for name in (key, *_alias(spec))
    ]


def _overrides(value: object) -> list[str]:
    """Names in npm `overrides`, which nest: a key is a package, a dict value scopes further overrides."""
    if not isinstance(value, dict):
        return []
    names: list[str] = []
    for key, spec in value.items():
        if key != ".":
            names.append(strip_range(key))
        names += _alias(spec) + _overrides(spec)
    return names


def _resolution_names(key: str) -> list[str]:
    """Packages a yarn resolution key names: `**/a`, `a/@s/b`, `a@^1`."""
    tokens = key.split("/")
    names: list[str] = []
    i = 0
    while i < len(tokens):
        if tokens[i].startswith("@") and i + 1 < len(tokens):
            names.append(strip_range(f"{tokens[i]}/{tokens[i + 1]}"))
            i += 2
            continue
        if tokens[i] not in ("", "*", "**"):
            names.append(strip_range(tokens[i]))
        i += 1
    return names


def _resolutions(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    return [name for key, spec in value.items() for name in (*_resolution_names(key), *_alias(spec))]


def _catalogs(owner: dict) -> list[str]:
    """pnpm/Bun catalogs: `catalog` maps names to specs, `catalogs` maps catalog names to such maps."""
    names = _table(owner.get("catalog"))
    named = owner.get("catalogs")
    for catalog in named.values() if isinstance(named, dict) else []:
        names += _table(catalog)
    return names


def package_json_names(text: str) -> list[str]:
    """Every package a package.json declares or overrides; workspace globs are local paths and not read."""
    data = json.loads(text.removeprefix("\ufeff"))
    if not isinstance(data, dict):
        return []
    names: list[str] = []
    for key in _TABLES:
        names += _table(data.get(key))
    for key in _BUNDLED:
        bundled = data.get(key)
        names += [n for n in bundled if isinstance(n, str)] if isinstance(bundled, list) else []
    pnpm = data.get("pnpm")
    names += _overrides(data.get("overrides")) + _resolutions(data.get("resolutions")) + _catalogs(data)
    names += _overrides(pnpm.get("overrides")) if isinstance(pnpm, dict) else []
    workspaces = data.get("workspaces")
    return names + (_catalogs(workspaces) if isinstance(workspaces, dict) else [])

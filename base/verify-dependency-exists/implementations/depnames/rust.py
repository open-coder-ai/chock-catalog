"""Cargo.toml: dependency, dev, build and target tables, workspace dependencies, renames and patches."""

from __future__ import annotations

import tomllib

_KINDS = ("dependencies", "dev-dependencies", "build-dependencies", "dev_dependencies", "build_dependencies")


def _crates(table: object) -> list[str]:
    """Crate names of a dependency table: a `package` rename names the crate the key stands for."""
    if not isinstance(table, dict):
        return []
    return [
        spec["package"] if isinstance(spec, dict) and isinstance(spec.get("package"), str) else key
        for key, spec in table.items()
    ]


def _kinds(owner: object) -> list[str]:
    if not isinstance(owner, dict):
        return []
    return [name for kind in _KINDS for name in _crates(owner.get(kind))]


def cargo_names(text: str) -> list[str]:
    """Every crate a Cargo.toml depends on, patches or replaces."""
    data = tomllib.loads(text.removeprefix("\ufeff"))
    names = _kinds(data) + _kinds(data.get("workspace"))
    targets = data.get("target")
    for target in targets.values() if isinstance(targets, dict) else []:
        names += _kinds(target)
    patches = data.get("patch")
    for registry in patches.values() if isinstance(patches, dict) else []:
        names += _crates(registry)
    replaced = data.get("replace")
    names += [key.split(":", 1)[0] for key in replaced] if isinstance(replaced, dict) else []
    return names

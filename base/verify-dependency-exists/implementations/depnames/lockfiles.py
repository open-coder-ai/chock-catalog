"""Lockfiles: every package a lock pins, so a transitive addition no manifest shows can still be asked about."""

from __future__ import annotations

import json
import re
import tomllib

_YARN_KEY = re.compile(r"""^["']?((?:@[^/@\s"']+/)?[^/@\s"']+)@""")
_PNPM_KEY = re.compile(r"""^ {2}["']?/?((?:@[^/@\s"']+/)?[^/@\s"']+)[@/]\d""")
_GEM_SPEC = re.compile(r"^ {4}([A-Za-z0-9_.-]+) \(")


def package_lock_names(text: str) -> list[str]:
    """npm lockfile: `packages` keys (the last node_modules segment) and the v1 `dependencies` tree."""
    data = json.loads(text.removeprefix("\ufeff"))
    names: list[str] = []

    def walk(tree: object) -> None:
        for key, value in tree.items() if isinstance(tree, dict) else []:
            names.append(key)
            walk(value.get("dependencies") if isinstance(value, dict) else None)

    packages = data.get("packages") if isinstance(data, dict) else None
    for key in packages if isinstance(packages, dict) else []:
        if "node_modules/" in key:
            names.append(key.rsplit("node_modules/", 1)[1])
    walk(data.get("dependencies") if isinstance(data, dict) else None)
    return names


def yarn_lock_names(text: str) -> list[str]:
    """Yarn lock: the package of the first descriptor of every entry header."""
    names = []
    for line in text.removeprefix("\ufeff").splitlines():
        if line and not line.startswith((" ", "#")) and (m := _YARN_KEY.match(line.split(",", 1)[0].strip())):
            names.append(m.group(1))
    return names


def pnpm_lock_names(text: str) -> list[str]:
    """pnpm lock: entries of the `packages`/`snapshots` maps, in the v5 `/name/1.0`, v6 and v9 key forms."""
    return [m.group(1) for line in text.removeprefix("\ufeff").splitlines() if (m := _PNPM_KEY.match(line))]


def toml_lock_names(text: str) -> list[str]:
    """poetry.lock, uv.lock and Cargo.lock: `name` of every [[package]]."""
    packages = tomllib.loads(text.removeprefix("\ufeff")).get("package")
    return (
        [p["name"] for p in packages if isinstance(p, dict) and isinstance(p.get("name"), str)]
        if isinstance(packages, list)
        else []
    )


def cargo_lock_names(text: str) -> list[str]:
    """Cargo.lock: crates with a `source`; the workspace's own crates have none and are not dependencies."""
    packages = tomllib.loads(text.removeprefix("\ufeff")).get("package")
    found = [p for p in packages if isinstance(p, dict)] if isinstance(packages, list) else []
    return [p["name"] for p in found if isinstance(p.get("name"), str) and "source" in p]


def go_sum_names(text: str) -> list[str]:
    """go.sum: the module of every line."""
    return [line.split()[0] for line in text.removeprefix("\ufeff").splitlines() if line.split()]


def gemfile_lock_names(text: str) -> list[str]:
    """Gemfile.lock: gems listed with a version at the specs indent."""
    return [m.group(1) for line in text.removeprefix("\ufeff").splitlines() if (m := _GEM_SPEC.match(line))]


def composer_lock_names(text: str) -> list[str]:
    """composer.lock: `name` of every entry in packages and packages-dev."""
    data = json.loads(text.removeprefix("\ufeff"))
    entries = [
        e for key in ("packages", "packages-dev") for e in (data.get(key) if isinstance(data, dict) else None) or []
    ]
    return [e["name"] for e in entries if isinstance(e, dict) and isinstance(e.get("name"), str)]

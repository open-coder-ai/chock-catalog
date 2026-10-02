"""npm package-lock.json / npm-shrinkwrap.json (lockfileVersion 1-3) and bun.lock (JSONC) readers."""

from __future__ import annotations

import json

from chock_scan import jsonc

from lockscan.model import Entry, Lines, LockError, https, split_spec, sri

MAX_CHARS = 1 << 26
DIRECT_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
MODULES = "node_modules/"
#: Spec prefixes that name no download at all: a workspace member or a symlink to a folder in the repo.
LOCAL = ("workspace:", "link:")
TARBALLS = (".tgz", ".tar.gz", ".tar")
#: A bun.lock registry package is [spec, registry URL or "", metadata, integrity].
INTEGRITY_AT = 3


def _object(text: str) -> dict:
    try:
        document = json.loads(text)
    except ValueError as exc:
        msg = f"not valid JSON ({exc})"
        raise LockError(msg) from exc
    if not isinstance(document, dict):
        msg = "not a JSON object"
        raise LockError(msg)
    return document


def _source_entry(name: str, version: str, raw: dict, line: int, *, transitive: bool) -> Entry:
    resolved = raw.get("resolved")
    if resolved is not None and not isinstance(resolved, str):
        msg = f"{name}: 'resolved' is not a string"
        raise LockError(msg)
    integrity, weak = sri(raw.get("integrity"))
    registry = https(resolved)
    return Entry(
        name=name,
        version=version,
        line=line,
        source=resolved,
        eco="npm",
        integrity=integrity,
        expect=registry,
        weak=weak,
        install=raw.get("hasInstallScript") is True,
        transitive=transitive,
        tarball=True,
    )


def package_lock(text: str) -> list[Entry]:
    document = _object(text)
    packages = document.get("packages")
    if isinstance(packages, dict):
        return _v2(Lines(text), packages)
    if "packages" in document:
        msg = "'packages' is not an object"
        raise LockError(msg)
    return _v1(Lines(text), document.get("dependencies") or {}, depth=0)


def _v2(lines: Lines, packages: dict) -> list[Entry]:
    root = packages.get("", {})
    direct = {n for key in DIRECT_KEYS if isinstance(root, dict) for n in (root.get(key) or {})}
    aliases = _aliases(packages)
    found = []
    for key, raw in packages.items():
        if not isinstance(raw, dict):
            msg = f"package {key!r} is not an object"
            raise LockError(msg)
        nested = key.count(MODULES) > 1
        if MODULES not in key or raw.get("link") is True or (raw.get("inBundle") is True and nested):
            continue  # the root, a workspace folder, a symlink, or a package shipped inside a dependency's tarball
        name = _installed_name(aliases, key, raw)
        transitive = nested or key.rsplit(MODULES, 1)[1] not in direct
        line = lines(json.dumps(key))
        found.append(_source_entry(name, str(raw.get("version", "")), raw, line, transitive=transitive))
    return found


def _aliases(packages: dict) -> set[tuple[str, str]]:
    """(folder, package) for every npm: alias any package in the lock declares; npm hoists an alias anywhere."""
    found = set()
    for raw in packages.values():
        for key in DIRECT_KEYS:
            deps = raw.get(key) if isinstance(raw, dict) else None
            for folder, spec in deps.items() if isinstance(deps, dict) else ():
                if isinstance(spec, str) and spec.startswith("npm:"):
                    found.add((folder, split_spec(spec[4:])[0]))
    return found


def _installed_name(aliases: set[tuple[str, str]], key: str, raw: dict) -> str:
    """The package a node_modules folder holds: its folder name, unless the lock declares that npm: alias.

    A `name` field alone does not count: npm installs whatever the lock resolves, so a forged name would let a
    registry URL for another package pass as this one's.
    """
    folder = key.rsplit(MODULES, 1)[1]
    named = raw.get("name")
    return named if isinstance(named, str) and (folder, named) in aliases else folder


def _v1(lines: Lines, deps: object, depth: int) -> list[Entry]:
    if not isinstance(deps, dict):
        msg = "'dependencies' is not an object"
        raise LockError(msg)
    found = []
    for name, raw in deps.items():
        if not isinstance(raw, dict):
            msg = f"dependency {name!r} is not an object"
            raise LockError(msg)
        version = str(raw.get("version", ""))
        if raw.get("bundled") is not True and not _folder(version):
            line = lines(json.dumps(name))
            real = split_spec(version[4:])[0] if version.startswith("npm:") else name  # an alias installs this one
            # v1 records a git or URL dependency in `version`, with no `resolved`
            fields = {**raw, "resolved": version} if ":" in version and "resolved" not in raw else raw
            found.append(_source_entry(real, version, fields, line, transitive=depth > 0))
        found += _v1(lines, raw.get("dependencies") or {}, depth + 1)
    return found


def _folder(version: str) -> bool:
    """A v1 spec naming a folder in the repository (v2 records these as links), not a tarball or a download."""
    return version.startswith(LOCAL) or (version.startswith("file:") and not version.endswith(TARBALLS))


def bun_lock(text: str) -> list[Entry]:
    try:
        loaded = jsonc.loads(text, limit=MAX_CHARS)
    except jsonc.JsoncError as exc:
        msg = f"not valid JSONC ({exc})"
        raise LockError(msg) from exc
    if loaded.duplicates:
        msg = f"a key given twice ({loaded.duplicates[0].path}), so one value hides the other"
        raise LockError(msg)
    document = loaded.value
    packages = document.get("packages") if isinstance(document, dict) else None
    if not isinstance(packages, dict):
        msg = "no 'packages' object"
        raise LockError(msg)
    found, lines = [], Lines(text)
    for key, raw in packages.items():
        if not isinstance(raw, list) or not raw or not isinstance(raw[0], str):
            msg = f"package {key!r} is not a [spec, ...] array"
            raise LockError(msg)
        name, version = split_spec(raw[0])
        if version.startswith(LOCAL):
            continue
        found.append(_bun_entry(name, version, raw, lines(json.dumps(key))))
    return found


def _bun_entry(name: str, version: str, raw: list, line: int) -> Entry:
    if ":" in version.split("#", 1)[0] and not version.startswith("npm:"):
        source = version  # a protocol other than an npm alias (github:, git+ssh:, https:, file:) is not the registry
    else:
        source = raw[1] if len(raw) > 1 and isinstance(raw[1], str) and raw[1] else None
    integrity, weak = sri(raw[INTEGRITY_AT] if len(raw) > INTEGRITY_AT else None)
    return Entry(
        name=name,
        version=version,
        line=line,
        source=source,
        eco="npm",
        integrity=integrity,
        expect=https(source),
        weak=weak,
    )

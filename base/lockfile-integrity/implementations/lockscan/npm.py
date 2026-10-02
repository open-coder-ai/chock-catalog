"""npm package-lock.json / npm-shrinkwrap.json (lockfileVersion 1-3) and bun.lock (JSONC) readers."""

from __future__ import annotations

import json

from chock_scan import jsonc

from lockscan.model import Entry, Lines, LockError, split_spec, sri

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
    integrity, weak = sri(raw.get("integrity"))
    registry = resolved is None or (isinstance(resolved, str) and resolved.startswith("https://"))
    return Entry(
        name=name,
        version=version,
        line=line,
        source=resolved if isinstance(resolved, str) else None,
        eco="npm",
        integrity=integrity,
        expect=registry,
        weak=weak,
        install=raw.get("hasInstallScript") is True,
        transitive=transitive,
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
    found = []
    for key, raw in packages.items():
        if not isinstance(raw, dict):
            msg = f"package {key!r} is not an object"
            raise LockError(msg)
        if MODULES not in key or raw.get("link") is True or raw.get("inBundle") is True:
            continue  # the root, a workspace folder, a symlink, or a package shipped inside its parent's tarball
        name = raw.get("name") if isinstance(raw.get("name"), str) else key.rsplit(MODULES, 1)[1]
        transitive = key.count(MODULES) > 1 or name not in direct
        line = lines(json.dumps(key))
        found.append(_source_entry(name, str(raw.get("version", "")), raw, line, transitive=transitive))
    return found


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
            # v1 records a git or URL dependency in `version`, with no `resolved`
            fields = {**raw, "resolved": version} if ":" in version and "resolved" not in raw else raw
            found.append(_source_entry(name, version, fields, line, transitive=depth > 0))
        found += _v1(lines, raw.get("dependencies") or {}, depth + 1)
    return found


def _folder(version: str) -> bool:
    """A v1 spec naming a folder in the repository (v2 records these as links), not a tarball or a download."""
    return version.startswith(LOCAL) or (version.startswith("file:") and not version.endswith(TARBALLS))


def bun_lock(text: str) -> list[Entry]:
    try:
        document = jsonc.loads(text, limit=MAX_CHARS).value
    except jsonc.JsoncError as exc:
        msg = f"not valid JSONC ({exc})"
        raise LockError(msg) from exc
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
    if ":" in version.split("#", 1)[0]:
        # npm:alias@x is still the registry; anything else with a protocol (github:, git+ssh:, https:, file:) is not.
        source = None if version.startswith("npm:") else version
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
        expect=source is None or source.startswith("https://"),
        weak=weak,
    )

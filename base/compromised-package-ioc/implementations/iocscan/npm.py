"""npm-family files: package.json and the npm, yarn, pnpm and bun lockfiles."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

from chock_scan import jsonc

from iocscan import Hit, UnparseableError, line_of

ECO = "npm"
SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
BUNDLED = ("bundleDependencies", "bundledDependencies")
#: Lockfiles of large monorepos run to tens of megabytes; this bounds the JSONC pass, not the guard.
LOCK_LIMIT = 1 << 26
SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
PNPM_KEY = re.compile(
    r"""\s+(?:\?\s+)?['"]?/?((?:@[^/@\s'"]+/)?[^/@\s'"()]+)[@/]([0-9][^\s:'"()_]*)[^:\s]*\s*(?::(?:\s*[{&!#].*)?)?\s*"""
)
YARN_VERSION = re.compile(r"""\s+version:?\s+"?([^"\s]+)"?\s*$""")


def exact(spec: object) -> str | None:
    """The version a spec pins exactly (`1.2.3`, `=1.2.3`, `v1.2.3`); None for a range, tag, URL or path."""
    if not isinstance(spec, str):
        return None
    found = spec.strip().lstrip("=").strip()
    found = found[1:] if found[:1] in ("v", "V") else found
    return found if SEMVER.fullmatch(found) else None


def split_at(descriptor: str) -> tuple[str, str]:
    """`name@rest` split at the `@` after any scope; rest is empty when there is none."""
    at = descriptor.find("@", 1)
    return (descriptor, "") if at < 0 else (descriptor[:at], descriptor[at + 1 :])


def _alias(name: str, spec: object, line: int) -> Iterator[Hit]:
    """A dependency, and for an `npm:real@spec` alias the real package too."""
    yield Hit(ECO, name, exact(spec), line)
    if isinstance(spec, str) and spec.strip().startswith("npm:"):
        real, real_spec = split_at(spec.strip()[4:])
        yield Hit(ECO, real, exact(real_spec), line)


def _load(text: str) -> dict:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        msg = f"not valid JSON ({exc})"
        raise UnparseableError(msg) from None
    if not isinstance(doc, dict):
        msg = "not a JSON object"
        raise UnparseableError(msg)
    return doc


def package_json(text: str) -> Iterator[Hit]:
    """Every dependency, bundled name, override and resolution package.json declares."""
    doc = _load(text)
    for section in SECTIONS:
        deps = doc.get(section)
        if isinstance(deps, dict):
            for name, spec in deps.items():
                yield from _alias(name, spec, line_of(text, f'"{name}"'))
    for section in BUNDLED:
        names = doc.get(section)
        if isinstance(names, list):
            yield from (Hit(ECO, n, None, line_of(text, f'"{n}"')) for n in names if isinstance(n, str))
    yield from _overrides(text, doc.get("overrides"))
    pnpm = doc.get("pnpm")
    yield from _overrides(text, pnpm.get("overrides") if isinstance(pnpm, dict) else None)
    resolutions = doc.get("resolutions")
    if isinstance(resolutions, dict):
        for key, spec in resolutions.items():
            yield from _alias(_resolution_name(key), spec, line_of(text, f'"{key}"'))


def _overrides(text: str, node: object) -> Iterator[Hit]:
    """npm `overrides`: a key is `name` or `name@range`; a value is a spec, or an object whose "." is one."""
    stack = [node]
    while stack:
        current = stack.pop()
        if not isinstance(current, dict):
            continue
        for key, value in current.items():
            if key == ".":
                continue
            name = split_at(key.rsplit(">", 1)[-1])[0]  # pnpm `parent>child` selects the child
            spec = value.get(".") if isinstance(value, dict) else value
            yield from _alias(name, spec, line_of(text, f'"{key}"'))
            stack.append(value)


def _resolution_name(key: str) -> str:
    """The package a yarn resolution key names: its last path segment, keeping a scope; any `@range` dropped."""
    parts = key.split("/")
    last = "/".join(parts[-2:]) if len(parts) > 1 and parts[-2].startswith("@") else parts[-1]
    return split_at(last)[0]


def package_lock(text: str) -> Iterator[Hit]:
    """npm-shrinkwrap.json and package-lock.json, v1 (nested dependencies) through v3 (packages)."""
    doc = _load(text)
    packages = doc.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue
            line = line_of(text, f'"{key}"')
            name = key.rsplit("node_modules/", 1)[1] if "node_modules/" in key else meta.get("name")
            if isinstance(name, str):
                yield from _alias(name, meta.get("version"), line)
            if isinstance(meta.get("name"), str) and meta["name"] != name:
                yield Hit(ECO, meta["name"], exact(meta.get("version")), line)
    stack = [doc.get("dependencies")]
    while stack:
        deps = stack.pop()
        if not isinstance(deps, dict):
            continue
        for name, meta in deps.items():
            if isinstance(meta, dict):
                yield from _alias(name, meta.get("version"), line_of(text, f'"{name}"'))
                stack.append(meta.get("dependencies"))


def yarn_lock(text: str) -> Iterator[Hit]:
    """yarn.lock, classic and berry: each entry's descriptors (aliases resolved) at its `version`."""
    names: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if line and not line[0].isspace() and not line.startswith("#") and line.rstrip().endswith(":"):
            names = []
            for raw in line.rstrip()[:-1].split(","):
                name, rest = split_at(raw.strip().strip("\"'"))
                names.append(name)
                if rest.startswith("npm:"):
                    names.append(split_at(rest[4:])[0])
        elif found := YARN_VERSION.match(line):
            yield from (Hit(ECO, n, exact(found.group(1)), number) for n in dict.fromkeys(names))


def pnpm_lock(text: str) -> Iterator[Hit]:
    """pnpm-lock.yaml, v5 (`/name/1.2.3:`) to v9 (`name@1.2.3:`): every package key, explicit (`? key`) or
    followed by a flow value, comment, tag or anchor; peer suffixes dropped."""
    for number, line in enumerate(text.splitlines(), 1):
        if found := PNPM_KEY.fullmatch(line):
            yield Hit(ECO, found.group(1), exact(found.group(2)), number)


def bun_lock(text: str) -> Iterator[Hit]:
    """bun.lock (JSONC): each `packages` entry's leading `name@version`."""
    try:
        doc = jsonc.loads(text, LOCK_LIMIT).value
    except jsonc.JsoncError as exc:
        msg = f"not valid JSONC ({exc})"
        raise UnparseableError(msg) from None
    packages = doc.get("packages") if isinstance(doc, dict) else None
    for key, entry in packages.items() if isinstance(packages, dict) else ():
        if isinstance(entry, list) and entry and isinstance(entry[0], str):
            name, version = split_at(entry[0])
            yield Hit(ECO, name, exact(version), line_of(text, f'"{key}"'))

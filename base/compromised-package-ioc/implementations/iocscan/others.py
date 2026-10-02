"""Go, Cargo, RubyGems and Composer manifests and lockfiles."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator

from iocscan import Hit, UnparseableError, line_of

SEMVER = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]*)?")
#: `require (` opens a block; a go.sum line is `module version hash`.
BLOCK_OPENER = 2
SUM_FIELDS = 2
CARGO_TABLES = ("dependencies", "dev-dependencies", "dev_dependencies", "build-dependencies", "build_dependencies")
GEM = re.compile(
    r"""(?:^|[\s;])(?:gem|\w+\.add_(?:runtime_|development_)?dependency)\s*\(?\s*['"]([^'"]+)['"]"""
    r"""((?:\s*,\s*['"][^'"]*['"])*)""",
    re.MULTILINE,
)
GEM_SPEC = re.compile(r"""['"]\s*=?\s*([0-9][0-9A-Za-z.]*)\s*['"]""")
GEM_LOCK = re.compile(r" {4}([A-Za-z0-9._-]+) \(([0-9][0-9A-Za-z.]*)[^)]*\)")


def _semver(spec: object, prefixes: str = "=") -> str | None:
    """`spec` as an exact version when, after at most one of `prefixes`, it is a full x.y.z version."""
    if not isinstance(spec, str):
        return None
    spec = spec.strip()
    spec = spec[1:].strip() if spec[:1] and spec[0] in prefixes else spec
    return spec if SEMVER.fullmatch(spec) else None


def go_mod(text: str) -> Iterator[Hit]:
    """go.mod `require` lines and blocks, and the target of each `replace`."""
    block = ""
    for number, raw in enumerate(text.splitlines(), 1):
        words = raw.split("//", 1)[0].split()
        if not words:
            continue
        if words[-1] == "(" and len(words) == BLOCK_OPENER:
            block = words[0]
            continue
        if words == [")"]:
            block = ""
            continue
        verb = block
        if words[0] in ("require", "replace", "exclude", "retract", "module", "go", "toolchain", "godebug"):
            verb, words = words[0], words[1:]
        if verb == "replace" and "=>" in words:
            words = words[words.index("=>") + 1 :]
        elif verb != "require":
            continue
        if words:
            yield Hit("go", words[0], _semver(words[1]) if len(words) > 1 else None, number)


def go_sum(text: str) -> Iterator[Hit]:
    """go.sum: every `module version[/go.mod] hash` line."""
    for number, line in enumerate(text.splitlines(), 1):
        words = line.split()
        if len(words) >= SUM_FIELDS:
            yield Hit("go", words[0], _semver(words[1].split("/", 1)[0]), number)


def _toml(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        msg = f"not valid TOML ({exc})"
        raise UnparseableError(msg) from None


def _cargo_deps(text: str, table: object) -> Iterator[Hit]:
    """`name = "spec"` or `name = { version, package }`; a rename is judged by the crate it fetches."""
    for key, spec in table.items() if isinstance(table, dict) else ():
        name = spec.get("package", key) if isinstance(spec, dict) else key
        version = spec.get("version") if isinstance(spec, dict) else spec
        if isinstance(name, str):
            yield Hit("crates", name, _semver(version, "=^"), line_of(text, key))


def cargo_toml(text: str) -> Iterator[Hit]:
    """Every dependency table: top level, per target, the workspace's, and [patch.*] overrides.

    A bare requirement is a caret range whose floor is the version written, so naming a listed version
    as the floor counts as naming it."""
    doc = _toml(text)
    scopes = [doc, doc.get("workspace")]
    targets = doc.get("target")
    scopes += list(targets.values()) if isinstance(targets, dict) else []
    for scope in scopes:
        for table in CARGO_TABLES:
            yield from _cargo_deps(text, scope.get(table) if isinstance(scope, dict) else None)
    patches = doc.get("patch")
    for table in patches.values() if isinstance(patches, dict) else ():
        yield from _cargo_deps(text, table)


def toml_lock(ecosystem: str, text: str) -> Iterator[Hit]:
    """Cargo.lock: each [[package]] name at its version."""
    packages = _toml(text).get("package")
    for item in packages if isinstance(packages, list) else ():
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            yield Hit(ecosystem, item["name"], _semver(item.get("version")), line_of(text, item["name"]))


def gemfile(text: str) -> Iterator[Hit]:
    """Gemfile `gem` lines and gemspec `add_*dependency` calls; a bare or `=` version is exact."""
    for found in GEM.finditer(text):
        pins = GEM_SPEC.findall(found.group(2))
        line = text.count("\n", 0, found.start(1)) + 1
        yield Hit("rubygems", found.group(1), pins[0] if len(pins) == 1 else None, line)


def gemfile_lock(text: str) -> Iterator[Hit]:
    """Gemfile.lock: each resolved `    name (version[-platform])` line."""
    for number, line in enumerate(text.splitlines(), 1):
        if found := GEM_LOCK.fullmatch(line):
            yield Hit("rubygems", found.group(1), found.group(2), number)


def _json(text: str) -> dict:
    try:
        doc = json.loads(text)
    except ValueError as exc:
        msg = f"not valid JSON ({exc})"
        raise UnparseableError(msg) from None
    if not isinstance(doc, dict):
        msg = "not a JSON object"
        raise UnparseableError(msg)
    return doc


def composer_json(text: str) -> Iterator[Hit]:
    """composer.json `require` and `require-dev`; a full version with no operator is exact."""
    doc = _json(text)
    for section in ("require", "require-dev"):
        deps = doc.get(section)
        for name, spec in deps.items() if isinstance(deps, dict) else ():
            yield Hit("packagist", name, _semver(spec, "=v"), line_of(text, f'"{name}"'))


def composer_lock(text: str) -> Iterator[Hit]:
    """composer.lock `packages` and `packages-dev` entries."""
    doc = _json(text)
    for section in ("packages", "packages-dev"):
        items = doc.get(section)
        for item in items if isinstance(items, list) else ():
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                yield Hit("packagist", item["name"], _semver(item.get("version")), line_of(text, item["name"]))

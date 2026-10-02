"""Cargo.lock, go.sum, Gemfile.lock, composer.lock and NuGet packages.lock.json readers."""

from __future__ import annotations

import json
import re

from lockscan.model import COMMIT, Entry, Lines, LockError
from lockscan.python import _fragment_pin, _packages, _toml

CRATES_IO = frozenset({"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"})
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
GO_SUM = re.compile(r"(\S+) (\S+) (h1:[A-Za-z0-9+/]{43}=)")
GEM_SPEC = re.compile(r" {4}(\S+) \(([^)]+)\)$")
GEM_CHECKSUM = re.compile(r" {2}(\S+) \(([^)]+)\)(?: (.*))?$")
GEM_ATTR = re.compile(r" {2}(remote|revision): (.+)$")
NUGET_SKIP = frozenset({"Project"})
GEM_SOURCES = frozenset({"GEM", "GIT", "PATH", "PLUGIN SOURCE"})
#: Sections whose specs come from the remote above them: the registry, or a git repository (bundler plugins too).
GIT_SPECS = frozenset({"GEM", "GIT", "PLUGIN SOURCE"})
GEM_SECTIONS = GEM_SOURCES | {"PLATFORMS", "DEPENDENCIES", "CHECKSUMS", "RUBY VERSION", "BUNDLED WITH"}


def cargo_lock(text: str) -> list[Entry]:
    document, lines = _toml(text), Lines(text)
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    found = []
    for pkg in _packages(document):
        name, version, source = str(pkg.get("name", "")), str(pkg.get("version", "")), pkg.get("source")
        line = lines(f'name = "{name}"')
        if source is None:
            continue  # a path crate in this workspace
        source = str(source)
        checksum = str(pkg.get("checksum") or metadata.get(f"checksum {name} {version} ({source})", ""))
        integrity = (checksum,) if SHA256_HEX.fullmatch(checksum) else ()
        if source.startswith("git+"):
            found.append(Entry(name, version, line, source, "cargo", integrity, git=True, pinned=_fragment_pin(source)))
            continue
        url = (
            None
            if source in CRATES_IO
            else source.split("+", 1)[1]
            if source.startswith(("registry+", "sparse+"))
            else source
        )
        found.append(Entry(name, version, line, url, "cargo", integrity, expect=True))
    return found


def go_sum(text: str) -> list[Entry]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = GO_SUM.fullmatch(line.rstrip("\r"))
        if not match:
            msg = f"line {number} is not 'module version h1:hash'"
            raise LockError(msg)
        found.append(Entry(match.group(1), match.group(2), number, integrity=(match.group(3),)))
    return found


def gemfile_lock(text: str) -> list[Entry]:
    found: list[Entry] = []
    checksums: dict[str, str] = {}
    section, attrs, seen = "", {}, set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r")
        if line and not line.startswith(" "):
            section, attrs = line.strip(), {}
            if section not in GEM_SECTIONS:
                msg = f"line {number}: unknown section {section[:40]!r}"
                raise LockError(msg)
            seen.add(section)
        elif section == "CHECKSUMS" and (match := GEM_CHECKSUM.match(line)):
            checksums[f"{match.group(1)}@{match.group(2)}"] = (match.group(3) or "").replace("=", ":", 1)
        elif section in GEM_SOURCES and (match := GEM_ATTR.match(line)):
            attrs.setdefault(match.group(1), []).append(match.group(2).strip())
            if match.group(1) == "remote" and section == "GEM":
                found.append(Entry("GEM remote", match.group(2).strip(), number, match.group(2).strip(), "gem"))
        elif section in GIT_SPECS and (match := GEM_SPEC.match(line)):
            found.append(_gem_spec(section, attrs, match, number))
    if not seen & GEM_SOURCES:
        msg = "no GEM, GIT or PATH section"
        raise LockError(msg)
    return [
        Entry(e.name, e.version, e.line, e.source, e.eco, _gem_hash(checksums.get(e.ident)), git=e.git, pinned=e.pinned)
        for e in found
    ]


def _gem_spec(section: str, attrs: dict[str, list[str]], match: re.Match, number: int) -> Entry:
    if not attrs.get("remote"):
        msg = f"line {number}: a {section} spec before any 'remote:'"
        raise LockError(msg)
    if section == "GEM":
        return Entry(match.group(1), match.group(2), number, None, "gem")
    revision = attrs.get("revision", [""])[-1]
    pinned = bool(COMMIT.fullmatch(revision))
    return Entry(match.group(1), match.group(2), number, attrs["remote"][-1], "gem", git=True, pinned=pinned)


def _gem_hash(value: str | None) -> tuple[str, ...]:
    return (value,) if value else ()


def _json_object(text: str) -> dict:
    try:
        document = json.loads(text)
    except ValueError as exc:
        msg = f"not valid JSON ({exc})"
        raise LockError(msg) from exc
    if not isinstance(document, dict):
        msg = "not a JSON object"
        raise LockError(msg)
    return document


def composer_lock(text: str) -> list[Entry]:
    document, lines = _json_object(text), Lines(text)
    found = []
    for section in ("packages", "packages-dev"):
        packages = document.get(section, [])
        if not isinstance(packages, list) or not all(isinstance(p, dict) for p in packages):
            msg = f"'{section}' is not an array of objects"
            raise LockError(msg)
        for pkg in packages:
            name, version = str(pkg.get("name", "")), str(pkg.get("version", ""))
            line = lines(f'"name": {json.dumps(name)}')
            dist = pkg.get("dist") if isinstance(pkg.get("dist"), dict) else {}
            source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
            if dist.get("type") == "path" or (not dist and source.get("type") == "path"):
                continue
            shasum = str(dist.get("shasum") or "")
            integrity = (shasum,) if shasum else ()
            if dist.get("url"):
                found.append(Entry(name, version, line, str(dist["url"]), "composer", integrity))
            elif source.get("url"):
                pinned = bool(COMMIT.fullmatch(str(source.get("reference", ""))))
                found.append(Entry(name, version, line, str(source["url"]), "composer", git=True, pinned=pinned))
    return found


def nuget_lock(text: str) -> list[Entry]:
    document, lines = _json_object(text), Lines(text)
    frameworks = document.get("dependencies", {})
    if not isinstance(frameworks, dict) or not all(isinstance(v, dict) for v in frameworks.values()):
        msg = "'dependencies' is not an object of target frameworks"
        raise LockError(msg)
    found = []
    for packages in frameworks.values():
        for name, raw in packages.items():
            if not isinstance(raw, dict):
                msg = f"package {name!r} is not an object"
                raise LockError(msg)
            if raw.get("type") in NUGET_SKIP:
                continue
            content = str(raw.get("contentHash") or "")
            line = lines(json.dumps(name))
            found.append(
                Entry(name, str(raw.get("resolved", "")), line, integrity=(content,) if content else (), expect=True)
            )
    return found

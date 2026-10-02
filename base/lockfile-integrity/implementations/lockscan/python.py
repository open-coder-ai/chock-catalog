"""poetry.lock and uv.lock (TOML) and Pipfile.lock (JSON) readers."""

from __future__ import annotations

import json
import tomllib

from lockscan.model import COMMIT, Entry, Lines, LockError, prefixed

LOCAL_SOURCES = frozenset({"directory", "file", "path", "editable", "virtual"})
PIPFILE_SECTIONS = ("default", "develop")


def _toml(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        msg = f"not valid TOML ({exc})"
        raise LockError(msg) from exc


def _packages(document: dict) -> list[dict]:
    packages = document.get("package", [])
    if not isinstance(packages, list) or not all(isinstance(p, dict) for p in packages):
        msg = "'package' is not an array of tables"
        raise LockError(msg)
    return packages


def _fragment_pin(url: str) -> bool:
    """A git URL as uv and Cargo lock it: the resolved commit follows '#'."""
    return bool(COMMIT.fullmatch(url.rpartition("#")[2])) if "#" in url else False


def poetry_lock(text: str) -> list[Entry]:
    document, lines = _toml(text), Lines(text)
    metadata = document.get("metadata")
    legacy = metadata.get("files") if isinstance(metadata, dict) else None  # lock format 1: hashes per name
    legacy = legacy if isinstance(legacy, dict) else {}
    found = []
    for pkg in _packages(document):
        name, version = str(pkg.get("name", "")), str(pkg.get("version", ""))
        source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
        kind = str(source.get("type", ""))
        if kind in LOCAL_SOURCES:
            continue
        files = pkg.get("files", legacy.get(name, legacy.get(name.lower(), [])))
        hashes = [f.get("hash") for f in files if isinstance(f, dict)] if isinstance(files, list) else []
        integrity, weak = prefixed(hashes)
        git = kind == "git"
        found.append(
            Entry(
                name=name,
                version=version,
                line=lines(f'name = "{name}"'),
                source=str(source["url"]) if "url" in source else None,
                eco="pypi",
                integrity=integrity,
                expect=not git,
                weak=weak,
                git=git,
                pinned=not git or bool(COMMIT.fullmatch(str(source.get("resolved_reference", "")))),
            )
        )
    return found


def uv_lock(text: str) -> list[Entry]:
    document, lines = _toml(text), Lines(text)
    found = []
    for pkg in _packages(document):
        source = pkg.get("source") if isinstance(pkg.get("source"), dict) else {}
        if LOCAL_SOURCES & source.keys():
            continue  # the project itself, a workspace member or a folder; no source at all is judged as no URL
        files = [pkg.get("sdist")] + (pkg.get("wheels") if isinstance(pkg.get("wheels"), list) else [])
        files = [f for f in files if isinstance(f, dict)]
        integrity, weak = prefixed([f.get("hash") for f in files])
        git = "git" in source
        url = str(source.get("git") or source.get("registry") or source.get("url") or "")
        name = str(pkg.get("name", ""))
        line = lines(f'name = "{name}"')
        found.append(
            Entry(
                name,
                str(pkg.get("version", "")),
                line,
                url,
                "pypi",
                integrity,
                not git,
                weak,
                git,
                not git or _fragment_pin(url),
            )
        )
        # Each download URL is judged too: a registry entry can still name an archive on another host.
        found += [Entry(name, str(pkg.get("version", "")), line, str(f["url"]), "pypi") for f in files if "url" in f]
    return found


def pipfile_lock(text: str) -> list[Entry]:
    try:
        document = json.loads(text)
    except ValueError as exc:
        msg = f"not valid JSON ({exc})"
        raise LockError(msg) from exc
    if not isinstance(document, dict):
        msg = "not a JSON object"
        raise LockError(msg)
    lines = Lines(text)
    meta = document.get("_meta") if isinstance(document.get("_meta"), dict) else {}
    found = [
        Entry("_meta.sources", str(src.get("name", "")), lines('"url"'), str(src.get("url", "")), "pypi")
        for src in meta.get("sources", [])
        if isinstance(src, dict)
    ]
    for section in PIPFILE_SECTIONS:
        packages = document.get(section, {})
        if not isinstance(packages, dict):
            msg = f"'{section}' is not an object"
            raise LockError(msg)
        found += [_pipfile_entry(name, raw, lines(json.dumps(name))) for name, raw in packages.items()]
    return [entry for entry in found if entry]


def _pipfile_entry(name: str, raw: object, line: int) -> Entry | None:
    if not isinstance(raw, dict):
        msg = f"package {name!r} is not an object"
        raise LockError(msg)
    if "path" in raw or (raw.get("editable") is True and "git" not in raw):
        return None
    integrity, weak = prefixed(raw.get("hashes", []) if isinstance(raw.get("hashes"), list) else [])
    version = str(raw.get("version", raw.get("ref", "")))
    if "git" in raw:
        pinned = bool(COMMIT.fullmatch(str(raw.get("ref", ""))))
        return Entry(name, version, line, str(raw["git"]), "pypi", integrity, weak=weak, git=True, pinned=pinned)
    source = str(raw["file"]) if "file" in raw else None
    return Entry(name, version, line, source, "pypi", integrity, expect=True, weak=weak)

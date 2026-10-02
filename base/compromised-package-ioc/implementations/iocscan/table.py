"""The IOC table (data/ioc.json, an EP12 `ioc` table): loaded, checked, and indexed by normalised name."""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from chock_scan import data_table

PATH = Path(__file__).resolve().parent.parent / "data" / "ioc.json"
KEYS = ("refresh", "packages", "actions", "files")
ECOSYSTEMS = ("npm", "pypi", "crates", "go", "rubygems", "packagist")
ANY = "*"
SHA = re.compile(r"[0-9a-f]{40}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_PEP503 = re.compile(r"[-_.]+")
_RELEASE = re.compile(r"([0-9]+(?:\.[0-9]+)*)(.*)", re.DOTALL)


class Entry(NamedTuple):
    """One listed package, action or file: what matched, and why it is listed."""

    name: str
    versions: frozenset[str] | None  # None: every version
    incident: str
    date: str
    source: str


def norm_name(ecosystem: str, name: str) -> str:
    """The registry's identity for a name: PEP 503 for PyPI, `_` as `-` for crates, case folded everywhere.

    Folding case where a registry keeps it (npm legacy names, RubyGems, Go paths on a case-insensitive
    host) can only add matches, never lose one."""
    name = name.strip()
    if ecosystem == "pypi":
        name = _PEP503.sub("-", name)
    elif ecosystem == "crates":
        name = name.replace("_", "-")
    return name.casefold()


def norm_version(ecosystem: str, version: str) -> str:
    """A version as listed: no leading `=`/`v`, npm build metadata dropped, PyPI releases compared numerically."""
    version = version.strip().lstrip("=").strip()
    if version[:1] in ("v", "V") and version[1:2].isdigit():
        version = version[1:]
    if ecosystem == "npm":
        version = version.split("+", 1)[0]
    if ecosystem == "pypi":
        found = _RELEASE.fullmatch(version)
        if found:
            parts = [int(p) for p in found.group(1).split(".")]
            while len(parts) > 1 and parts[-1] == 0:
                parts.pop()
            version = ".".join(map(str, parts)) + found.group(2).casefold()
    return version


class Table:
    """Lookups over a loaded table; `package` and `action` return the listed entry or None."""

    def __init__(self, doc: dict) -> None:
        self.packages: dict[tuple[str, str], Entry] = {}
        for item in doc["packages"]:
            eco = item["ecosystem"]
            versions = item["versions"]
            listed = None if versions == ANY else frozenset(norm_version(eco, v) for v in versions)
            key = (eco, norm_name(eco, item["name"]))
            self.packages[key] = Entry(item["name"], listed, item["incident"], item["date"], item["source"])
        self.actions: dict[str, tuple[Entry, bool]] = {}
        for item in doc["actions"]:
            refs = frozenset(r.casefold() for r in item["refs"])
            entry = Entry(item["name"], refs, item["incident"], item["date"], item["source"])
            self.actions[item["name"].casefold()] = (entry, item["mutable_refs"])
        self.files = [
            (item["name"].casefold(), Entry(item["name"], None, item["incident"], item["date"], item["source"]))
            for item in doc["files"]
        ]

    def package(self, ecosystem: str, name: str, version: str | None) -> Entry | None:
        """The entry when `name` at `version` is listed; a version of None (a range, a URL) matches only ANY."""
        entry = self.packages.get((ecosystem, norm_name(ecosystem, name)))
        if entry is None:
            return None
        if entry.versions is None:
            return entry
        return entry if version is not None and norm_version(ecosystem, version) in entry.versions else None

    def action(self, name: str, ref: str) -> Entry | None:
        """The entry when `uses: name@ref` is a listed commit, or a tag or branch of an action listed as re-pointed."""
        listed = self.actions.get(name.casefold())
        if listed is None:
            return None
        entry, mutable = listed
        ref = ref.casefold()
        return entry if ref in entry.versions or (mutable and not SHA.fullmatch(ref)) else None

    def file(self, path: str) -> Entry | None:
        """The entry whose name is this path's basename, or for a name holding `/`, its trailing segments."""
        path = "/" + path.casefold().lstrip("/")
        for name, entry in self.files:
            if path.endswith("/" + name):
                return entry
        return None


def _problems(doc: dict) -> list[str]:
    """Every reason the payload is unusable; an empty list when it is."""
    out = [] if isinstance(doc["refresh"], str) and doc["refresh"] else ["refresh must be a non-empty string"]
    sources = doc["source"] if isinstance(doc["source"], dict) else {}
    seen: set[tuple[str, str]] = set()
    for i, item in enumerate(doc["packages"]):
        out += _package_problems(f"packages[{i}]", item, sources, seen)
    for i, item in enumerate(doc["actions"]):
        out += _action_problems(f"actions[{i}]", item, sources)
    for i, item in enumerate(doc["files"]):
        where = f"files[{i}]"
        out += _common(where, item, sources, {"name"})
        if item["name"] != item["name"].strip("/") or "\\" in item["name"] or ".." in item["name"].split("/"):
            out.append(f"{where}.name must be a relative path with no .., \\ or outer /")
    return out


def _package_problems(where: str, item: object, sources: dict, seen: set[tuple[str, str]]) -> list[str]:
    out = _common(where, item, sources, {"ecosystem", "name", "versions"})
    if item["ecosystem"] not in ECOSYSTEMS:
        return [*out, f"{where}.ecosystem must be one of {', '.join(ECOSYSTEMS)}"]
    versions = item["versions"]
    if versions != ANY and not (isinstance(versions, list) and versions and all(_text(v) for v in versions)):
        out.append(f"{where}.versions must be {ANY!r} or a non-empty list of versions")
    key = (item["ecosystem"], norm_name(item["ecosystem"], item["name"]))
    if key in seen:
        out.append(f"{where} repeats {key[0]} {key[1]}")
    seen.add(key)
    return out


def _action_problems(where: str, item: object, sources: dict) -> list[str]:
    out = _common(where, item, sources, {"name", "refs", "mutable_refs"})
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", item["name"]):
        out.append(f"{where}.name must be owner/repo")
    if not isinstance(item["refs"], list) or not all(isinstance(r, str) and SHA.fullmatch(r) for r in item["refs"]):
        out.append(f"{where}.refs must be a list of 40-hex lowercase commits")
    if not isinstance(item["mutable_refs"], bool) or not (item["refs"] or item["mutable_refs"]):
        out.append(f"{where} must list refs or set mutable_refs true")
    return out


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _common(where: str, item: object, sources: dict, keys: set[str]) -> list[str]:
    """Key set, text fields, date and source id shared by every row; a wrong shape stops at the first problem."""
    want = keys | {"incident", "date", "source"}
    if not isinstance(item, dict) or set(item) != want:
        msg = f"{where} must be an object with exactly {', '.join(sorted(want))}"
        raise ValueError(msg)
    out = [f"{where}.{k} must be non-empty text" for k in ("name", "incident") if not _text(item[k])]
    if not (isinstance(item["date"], str) and DATE.fullmatch(item["date"])):
        out.append(f"{where}.date must be YYYY-MM-DD")
    if item["source"] not in sources:
        out.append(f"{where}.source must name a key of the table's source object")
    return out


def load(path: Path = PATH) -> Table:
    """The table at `path`; raises data_table.TableError naming every problem."""
    return Table(data_table.load(path, kind="ioc", schema=1, keys=KEYS, check=_problems))

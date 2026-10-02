"""pnpm-lock.yaml reader (lockfile v5 to v9) through the EP01 YAML key-path scanner."""

from __future__ import annotations

from chock_scan import yamlpath

from lockscan.model import COMMIT, Entry, LockError, split_spec, sri

MAX_CHARS = 1 << 26
MAX_NODES = 5_000_000
DIRECT_KEYS = frozenset({"dependencies", "devDependencies", "optionalDependencies"})
PACKAGES = "packages"
LOCAL_TYPES = frozenset({"directory", "path"})
#: Path lengths: (packages, key), its fields, and resolution fields; importer and v5 root dependency names.
ENTRY, FIELD, RESOLUTION = 2, 3, 4
IMPORTER_DEP, ROOT_DEP = 4, 2


def pnpm_lock(text: str) -> list[Entry]:
    try:
        nodes = yamlpath.scan(text, max_chars=MAX_CHARS, max_nodes=MAX_NODES)
    except yamlpath.ParseError as exc:
        msg = f"not readable YAML ({exc})"
        raise LockError(msg) from exc
    if yamlpath.unknown(nodes, ()):
        msg = "an alias, merge key or repeated key: a loader may read entries the scan cannot see"
        raise LockError(msg)
    direct: set[str] = set()
    fields: dict[str, dict[str, str]] = {}
    lines: dict[str, int] = {}
    for node in nodes:
        path = node.path
        if _direct(path):
            direct.add(str(path[-1]))
        if not path or path[0] != PACKAGES or len(path) < ENTRY:
            continue
        key = str(path[1])
        if len(path) == ENTRY:
            lines[key] = node.line
            fields.setdefault(key, {})
        elif len(path) == FIELD or (len(path) == RESOLUTION and path[2] == "resolution"):
            fields[key]["/".join(map(str, path[2:]))] = node.value
    return [entry for key, got in fields.items() if (entry := _entry(key, got, lines[key], direct))]


def _direct(path: tuple[str | int, ...]) -> bool:
    """A dependency name an importer (v6+) or the v5 root lists: those packages are not transitive."""
    if len(path) == IMPORTER_DEP and path[0] == "importers":
        return path[2] in DIRECT_KEYS
    return len(path) == ROOT_DEP and path[0] in DIRECT_KEYS


def _ident(key: str) -> tuple[str, str]:
    """(name, version) of a packages key: '/name/1.0.0' (v5), '/name@1.0.0' (v6), 'name@1.0.0(peer@2)' (v9)."""
    bare = key.removeprefix("/")
    name, version = split_spec(bare)
    if name.count("/") != (1 if name.startswith("@") else 0):
        # v5: the '@' found was in a peer suffix (`_react@17`), not after the name
        name, _, version = bare.rpartition("/")
        return name, version.split("_", 1)[0]
    return name, version if "://" in version else version.split("(", 1)[0]


def _entry(key: str, got: dict[str, str], line: int, direct: set[str]) -> Entry | None:
    name, version = _ident(key)
    if got.get("resolution/type") in LOCAL_TYPES or "resolution/directory" in got or version.startswith("link:"):
        return None  # a folder in the repository: nothing is downloaded
    integrity, weak = sri(got.get("resolution/integrity"))
    source = got.get("resolution/tarball") or got.get("resolution/repo")
    if source is None and version.startswith("file:"):
        source = version
    git = got.get("resolution/type") == "git"
    return Entry(
        name=name,
        version=got.get("version", version),
        line=line,
        source=source,
        eco="npm",
        integrity=integrity,
        expect=not git and (source is None or source.startswith("https://")),
        weak=weak,
        pinned=not git or bool(COMMIT.fullmatch(got.get("resolution/commit", ""))),
        install=got.get("requiresBuild") == "true",
        transitive=name not in direct,
    )

"""yarn.lock readers: the classic (v1) line format, and the Berry (v2+) format through the EP01 YAML scanner."""

from __future__ import annotations

import json
import re
from dataclasses import replace

from chock_scan import yamlpath

from lockscan.model import COMMIT, Entry, LockError, https, split_spec, sri

MAX_CHARS = 1 << 26
MAX_NODES = 5_000_000
FIELDS = ("version", "resolved", "integrity")
SHA1_FRAGMENT = re.compile(r"#([0-9a-f]{40})$")
FOLDER = ("link:", "workspace:", "portal:")
TARBALLS = (".tgz", ".tar.gz", ".tar")
BERRY_LOCAL = ("workspace:", "link:", "portal:")
ARCHIVE_URL = "__archiveUrl"
#: What Berry reads as a git repository: a git scheme, a .git path, or a GitHub repository URL (not a tarball).
BERRY_GIT = re.compile(r"^(?:git[+:]|github:)|\.git/?$|^https://github\.com/[^/]+/[^/]+/?$", re.IGNORECASE)
SELECTORS = frozenset({"commit", "head", "tag", "semver"})
PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")
#: Classic header specs as yarn's tokenizer splits them: a comma outside quotes ends one, spaces or not.
HEADER_PART = re.compile(r'\s*(?:"(?:[^"\\]|\\.)*"|[^,"]+)')
#: Classic: a field is indented two spaces, a nested map's entries four. Berry: (entry, field) paths.
FIELD, NESTED, BERRY_FIELD = 2, 4, 2


def yarn_lock(text: str) -> list[Entry]:
    if re.search(r"^__metadata:", text, re.MULTILINE):
        return _berry(text)
    return [entry for header, fields, line in _classic_blocks(text) if (entry := _classic(header, fields, line))]


def _unquote(value: str) -> str:
    if value.startswith('"'):
        try:
            loaded = json.loads(value)
        except ValueError as exc:
            msg = f"a quoted value that does not close: {value[:40]!r}"
            raise LockError(msg) from exc
        return str(loaded)
    return value


def _classic_blocks(text: str) -> list[tuple[list[str], dict[str, str], int]]:
    """(specs of the header, its two-space fields, header line) per entry; LockError on any other shape."""
    blocks: list[tuple[list[str], dict[str, str], int]] = []
    nested = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\r")
        body = line.lstrip(" ")
        if not body or body.startswith("#"):
            continue
        indent = len(line) - len(body)
        if body[0] == "\t" or (indent == 0 and not line.endswith(":")):
            msg = f"line {number} is not a yarn.lock entry, field or comment"
            raise LockError(msg)
        if indent == 0:
            specs = [_unquote(part.strip()) for part in HEADER_PART.findall(line[:-1]) if part.strip()]
            blocks.append((specs, {}, number))
            nested = False
        elif not blocks or indent not in (FIELD, NESTED) or (indent == NESTED and not nested):
            msg = f"line {number} is indented where no entry or field holds it"
            raise LockError(msg)
        elif indent == FIELD:
            nested = _field(blocks[-1][1], body, number)
    return blocks


def _field(fields: dict[str, str], body: str, number: int) -> bool:
    """Record one two-space field; True when it opens a nested map (dependencies:)."""
    if body.endswith(":") and " " not in body:
        return True
    key, _, value = body.partition(" ")
    key = _unquote(key).removesuffix(":")  # the parser also reads `resolved: "url"`
    if key in fields:
        msg = f"line {number} repeats the field {key!r}, so one copy hides the other"
        raise LockError(msg)
    fields[key] = _unquote(value.strip())
    return False


def _installs(spec: str) -> tuple[str, str]:
    """(folder name, package installed) for one header spec; `alias@npm:real@^1` installs real."""
    name, wanted = split_spec(spec)
    return name, split_spec(wanted[4:])[0] if wanted.startswith("npm:") else name


def _classic(specs: list[str], fields: dict[str, str], line: int) -> Entry | None:
    _, spec = split_spec(specs[0])
    pairs = [_installs(s) for s in specs]
    name = pairs[0][1]
    # every spec in the header gets this one download: a name it does not install is a swap or an alias
    swapped = any(folder != name or real != name for folder, real in pairs)
    resolved = fields.get("resolved")
    if resolved is None and (spec.startswith(FOLDER) or (spec.startswith("file:") and not spec.endswith(TARBALLS))):
        return None  # a folder in the repository: nothing is downloaded
    integrity, weak = sri(fields.get("integrity"))
    download = https(resolved)
    sha1 = SHA1_FRAGMENT.search(resolved or "") if download else None
    if not integrity and sha1:
        integrity, weak = (f"sha1hex-{sha1.group(1)}",), True
    return Entry(
        name=name,
        version=fields.get("version", ""),
        line=line,
        source=resolved,
        eco="npm",
        integrity=integrity,
        expect=download,
        weak=weak,
        tarball=True,
        alias=swapped,
    )


def _berry(text: str) -> list[Entry]:
    try:
        nodes = yamlpath.scan(text, max_chars=MAX_CHARS, max_nodes=MAX_NODES)
    except yamlpath.ParseError as exc:
        msg = f"not readable YAML ({exc})"
        raise LockError(msg) from exc
    if yamlpath.unknown(nodes, ()):
        msg = "an alias, merge key or repeated key: a loader may read entries the scan cannot see"
        raise LockError(msg)
    blocks: dict[str, dict[str, str]] = {}
    lines: dict[str, int] = {}
    for node in nodes:
        if len(node.path) == 1:
            lines[str(node.path[0])] = node.line
            blocks.setdefault(str(node.path[0]), {})
        elif len(node.path) == BERRY_FIELD:
            blocks[str(node.path[0])][str(node.path[1])] = node.value
    found = []
    cache = blocks.get("__metadata", {}).get("cacheKey", "")
    for key, fields in blocks.items():
        if key == "__metadata":
            continue
        if "resolution" not in fields:
            msg = f"entry {key!r} has no resolution"
            raise LockError(msg)
        if entry := _berry_entry(fields, lines[key], cache):
            # the descriptor names the package asked for; a resolution naming another one installs that instead
            asked = {split_spec(descriptor.strip())[0] for descriptor in key.split(",")}
            found.append(replace(entry, alias=True) if asked != {entry.name} else entry)
    return found


def _decode(text: str) -> str:
    return PERCENT.sub(lambda m: chr(int(m.group(1), 16)), text)


def _berry_ref(ref: str) -> tuple[str | None, bool, bool]:
    """(source, from the registry, local) of a Berry reference; a patch: is judged by the reference it wraps."""
    ref, _, params = ref.partition("::")
    for pair in params.split("&"):
        key, _, value = pair.partition("=")
        if _decode(key) == ARCHIVE_URL:
            return _decode(value), False, False  # npm:x::__archiveUrl=<url> fetches that URL instead
    if ref.startswith("patch:"):
        return _berry_ref(split_spec(_decode(ref.removeprefix("patch:").split("#", 1)[0]))[1])
    if ref.startswith(BERRY_LOCAL):
        return None, False, True
    return (None, True, False) if ref.startswith("npm:") else (ref, False, False)


def _git_pin(source: str | None) -> tuple[bool, bool]:
    """(git, pinned) as Berry reads a reference: the part after the first '#' is a query string of selectors, or a
    bare committish; pinned only by one full commit id and no head, tag or semver selector beside it."""
    if not source:
        return False, True
    base, hashed, fragment = source.partition("#")
    pairs = [pair.partition("=") for pair in fragment.split("&")] if "=" in fragment else []
    keys = [_decode(key) for key, _, _ in pairs]
    git = bool(BERRY_GIT.search(base)) or bool(SELECTORS & set(keys))
    if not git:
        return False, True
    if not pairs:
        return True, bool(hashed) and bool(COMMIT.fullmatch(fragment))
    commits = [_decode(value) for key, _, value in pairs if _decode(key) == "commit"]
    others = SELECTORS - {"commit"}
    return True, len(commits) == 1 and bool(COMMIT.fullmatch(commits[0])) and not others & set(keys)


def _berry_entry(fields: dict[str, str], line: int, cache: str) -> Entry | None:
    name, ref = split_spec(fields["resolution"])
    source, registry, local = _berry_ref(ref)
    if local:
        return None
    checksum = fields.get("checksum", "")
    prefix, slash, _ = checksum.rpartition("/")
    if slash and prefix != cache:
        msg = f"{name}: a checksum under cache key {prefix!r} in a lock whose cache key is {cache!r}"
        raise LockError(msg)
    if checksum and not slash:
        checksum = f"{cache}/{checksum}"  # the cache key decides how a checksum is computed; compare like with like
    git, pinned = _git_pin(source)
    return Entry(
        name=name,
        version=fields.get("version", ""),
        line=line,
        source=source,
        eco="npm",
        integrity=(f"berry{checksum}",) if checksum else (),
        expect=registry,
        git=git and source.startswith(("https://", "git+https://")),
        pinned=pinned,
    )

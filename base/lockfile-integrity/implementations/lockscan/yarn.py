"""yarn.lock readers: the classic (v1) line format, and the Berry (v2+) format through the EP01 YAML scanner."""

from __future__ import annotations

import json
import re

from chock_scan import yamlpath

from lockscan.model import COMMIT, Entry, LockError, split_spec, sri

MAX_CHARS = 1 << 26
MAX_NODES = 5_000_000
FIELDS = ("version", "resolved", "integrity")
SHA1_FRAGMENT = re.compile(r"#([0-9a-f]{40})$")
FOLDER = ("link:", "workspace:", "portal:")
TARBALLS = (".tgz", ".tar.gz", ".tar")
BERRY_LOCAL = ("workspace:", "link:", "portal:")
ARCHIVE_URL = "__archiveUrl="
PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")


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
        if not isinstance(loaded, str):
            msg = f"a quoted value that is not a string: {value[:40]!r}"
            raise LockError(msg)
        return loaded
    return value


def _classic_blocks(text: str) -> list[tuple[str, dict[str, str], int]]:
    """(first spec of the header, its two-space fields, header line) per entry; LockError on any other shape."""
    blocks: list[tuple[str, dict[str, str], int]] = []
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
            blocks.append((_unquote(line[:-1].split(", ", 1)[0].strip()), {}, number))
            nested = False
        elif not blocks or indent not in (2, 4) or (indent == 4 and not nested):  # noqa: PLR2004
            msg = f"line {number} is indented where no entry or field holds it"
            raise LockError(msg)
        elif indent == 2:  # noqa: PLR2004
            nested = _field(blocks[-1][1], body, number)
    return blocks


def _field(fields: dict[str, str], body: str, number: int) -> bool:
    """Record one two-space field; True when it opens a nested map (dependencies:)."""
    if body.endswith(":") and " " not in body:
        return True
    key, _, value = body.partition(" ")
    key = _unquote(key)
    if key in fields:
        msg = f"line {number} repeats the field {key!r}, so one copy hides the other"
        raise LockError(msg)
    fields[key] = _unquote(value.strip())
    return False


def _classic(header: str, fields: dict[str, str], line: int) -> Entry | None:
    name, spec = split_spec(header)
    resolved = fields.get("resolved")
    if resolved is None and (spec.startswith(FOLDER) or (spec.startswith("file:") and not spec.endswith(TARBALLS))):
        return None  # a folder in the repository: nothing is downloaded
    integrity, weak = sri(fields.get("integrity"))
    sha1 = SHA1_FRAGMENT.search(resolved or "")
    if not integrity and sha1:
        integrity, weak = (f"sha1hex-{sha1.group(1)}",), True
    return Entry(
        name=name,
        version=fields.get("version", ""),
        line=line,
        source=resolved,
        eco="npm",
        integrity=integrity,
        expect=resolved is None or resolved.startswith("https://"),
        weak=weak,
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
        elif len(node.path) == 2:  # noqa: PLR2004
            blocks[str(node.path[0])][str(node.path[1])] = node.value
    found = []
    for key, fields in blocks.items():
        if key == "__metadata":
            continue
        if "resolution" not in fields:
            msg = f"entry {key!r} has no resolution"
            raise LockError(msg)
        if entry := _berry_entry(fields, lines[key]):
            found.append(entry)
    return found


def _berry_entry(fields: dict[str, str], line: int) -> Entry | None:
    name, ref = split_spec(fields["resolution"])
    if ref.startswith(BERRY_LOCAL):
        return None
    checksum = fields.get("checksum", "")
    registry = ref.startswith(("npm:", "patch:")) and ARCHIVE_URL not in ref
    if ARCHIVE_URL in ref:
        # npm:1.0.0::__archiveUrl=<url> fetches the archive from that URL instead of the registry.
        source = PERCENT.sub(lambda m: chr(int(m.group(1), 16)), ref.split(ARCHIVE_URL, 1)[1].split("&", 1)[0])
    else:
        source = None if registry else ref
    return Entry(
        name=name,
        version=fields.get("version", ""),
        line=line,
        source=source,
        eco="npm",
        integrity=(checksum,) if checksum else (),
        expect=ref.startswith("npm:"),
        pinned=not ref.startswith(("git", "github:")) or bool(COMMIT.search(ref)),
    )

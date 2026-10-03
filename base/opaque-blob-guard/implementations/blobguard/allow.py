"""The blob allowlist: `<sha256>  <path>` lines, `#` comments; one malformed line and nothing is allowed."""

from __future__ import annotations

import re
from typing import NamedTuple

from blobguard.source import read_git
from blobguard.tables import Tables
from chock_scan.safe_read import UnreadableError, decode

LIMIT = 1 << 20
#: sha256sum's text and binary forms: hash, one space, then a space or `*`, then the path.
LINE = re.compile(r"([0-9a-f]{64}) [ *](\S(?:.*\S)?)")
BAD_PATH = re.compile(r"^/|^\./|\\|//|/$|(?:^|/)\.\.?(?:/|$)")


class Allow(NamedTuple):
    """The (path, sha256) pairs a person approved; `problem` is why the whole list was refused, if it was."""

    entries: frozenset[tuple[str, str]]
    problem: str | None


def parse(text: str) -> Allow:
    """Every entry, or no entry and the first malformed line's number."""
    entries = set()
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = LINE.fullmatch(line)
        if match is None or BAD_PATH.search(match[2]):
            return Allow(frozenset(), f"allowlist line {number} is not '<sha256>  <path>'")
        entries.add((match[2], match[1]))
    return Allow(frozenset(entries), None)


def load(root: str, tables: Tables, *, committed_only: bool) -> Allow:
    """The allowlist as staged, or as HEAD has it when an agent's change must not approve its own blob.

    The index, not the working tree, so an unstaged edit approves nothing. Absent means an empty list;
    too large or not UTF-8 text means the whole list is refused.
    """
    rel = tables.allowlist
    blob = read_git(root, f"{'HEAD' if committed_only else ''}:./{rel}")
    if blob is None:
        return Allow(frozenset(), None)
    if blob.size > LIMIT:
        return Allow(frozenset(), f"{rel} is larger than {LIMIT} bytes")
    try:
        return parse(decode(blob.head, rel))
    except UnreadableError as exc:
        return Allow(frozenset(), str(exc))

"""Reading sibling files a detector needs (a manifest above a script, a gyp source), from the change or the tree."""

from __future__ import annotations

import os
import posixpath

from chock_scan import safe_read

#: How far above a written file a manifest is looked for; deeper trees are judged from their own manifests.
MAX_DEPTH = 12


def inside(root: str, rel: str) -> str | None:
    """The absolute path of `rel` under the repository root, or None when it would leave it."""
    if not root or rel.startswith("../") or rel == ".." or posixpath.isabs(rel):
        return None
    return os.path.join(root, *rel.split("/"))


def exists(rel: str, writes: dict[str, str], root: str) -> bool:
    if rel in writes:
        return True
    full = inside(root, rel)
    return bool(full) and os.path.isfile(full)


def text_of(rel: str, writes: dict[str, str], root: str) -> str | None:
    """A file's text from the change, else from disk; None when absent or not readable as text."""
    if rel in writes:
        return writes[rel]
    full = inside(root, rel)
    try:
        return safe_read.read_text(full) if full else None
    except safe_read.UnreadableError:
        return None


def ancestors(path: str) -> list[str]:
    """The folders holding `path`, nearest first, ending at the repository root ("")."""
    found, folder = [], posixpath.dirname(path)
    while len(found) < MAX_DEPTH:
        found.append(folder)
        if not folder:
            break
        folder = posixpath.dirname(folder)
    return found


def join(folder: str, rel: str) -> str:
    return posixpath.normpath(posixpath.join(folder or ".", rel.replace("\\", "/")))

"""gradle-wrapper.jar: a changed wrapper needs a new distributionSha256Sum in the same change, or a known hash."""

from __future__ import annotations

import posixpath
import re

from blobguard.source import Blob, read_git
from blobguard.tables import Tables

JAR = "gradle-wrapper.jar"
PROPS = "gradle-wrapper.properties"
SUM = re.compile(r"(?mi)^[ \t]*distributionSha256Sum[ \t]*[=:][ \t]*([0-9a-f]{64})[ \t]*$")


def is_wrapper_jar(rel: str) -> bool:
    return posixpath.basename(rel) == JAR


def _sum(text: str | None) -> str | None:
    found = SUM.search(text or "")
    return found[1].lower() if found else None


def wrapper_hit(rel: str, blob: Blob, writes: dict[str, str], root: str, tables: Tables) -> str | None:
    """Why this wrapper jar is not accepted, or None: a known hash, or a sum added or changed beside it.

    The properties file counts only when it is part of this change (`writes`) and its sum differs from
    HEAD's, so an unchanged sum, a removed one and a properties file left alone all ask.
    """
    if blob.sha in tables.known_wrappers:
        return None
    props = posixpath.join(posixpath.dirname(rel), PROPS)
    new = _sum(writes.get(props))
    old = read_git(root, f"HEAD:{props}")
    if new is not None and new != _sum(old.head.decode("latin-1") if old else None):
        return None
    return f"{JAR} changed without a new distributionSha256Sum in {PROPS} (or a known hash)"

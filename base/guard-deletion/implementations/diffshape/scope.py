"""Which paths guard-deletion judges: everything the scope table does not name (tests, docs, vendored code)."""

from __future__ import annotations

import fnmatch
import os

from chock_scan import data_table

KEYS = ("root_dirs", "dirs", "names", "suffixes")


def _check(doc: dict) -> list[str]:
    out = []
    for key in KEYS:
        value = doc[key]
        if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
            out.append(f"{key} must be a non-empty list of non-empty strings")
    return out


def load(path: str | os.PathLike[str]) -> dict[str, tuple[str, ...]]:
    """The validated scope table as lower-case tuples; raises data_table.TableError."""
    doc = data_table.load(path, kind="curated", schema=1, keys=KEYS, check=_check)
    return {key: tuple(v.lower() for v in doc[key]) for key in KEYS}


def in_scope(path: str, scope: dict[str, tuple[str, ...]]) -> bool:
    """False for a path under a listed directory, with a listed name pattern, or with a listed suffix."""
    parts = [p for p in path.replace("\\", "/").lower().split("/") if p not in ("", ".")]
    if not parts:
        return False
    name = parts[-1]
    if (parts[0] in scope["root_dirs"] and len(parts) > 1) or set(parts[:-1]) & set(scope["dirs"]):
        return False
    if name.endswith(scope["suffixes"]):
        return False
    return not any(fnmatch.fnmatchcase(name, pattern) for pattern in scope["names"])

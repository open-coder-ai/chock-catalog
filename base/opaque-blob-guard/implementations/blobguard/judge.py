"""Judge the in-scope paths of one change: findings keyed by rule and content hash, never by line."""

from __future__ import annotations

import os
import posixpath
from typing import NamedTuple

from blobguard.allow import Allow
from blobguard.detect import high_entropy, is_build_text, magic, text_hits
from blobguard.gradle import is_wrapper_jar, wrapper_hit
from blobguard.source import Blob, Link, Unreadable, from_bytes, read_disk, read_git
from blobguard.tables import Tables

#: Events that are an agent's: its change may not approve its own blob, nor judge only the working tree.
AGENT_EVENTS = frozenset({"tool_use", "agent-commit"})


class Hit(NamedTuple):
    rule: str
    line: int
    message: str
    sha: str | None


def in_blob_scope(rel: str, tables: Tables) -> bool:
    """Under a scoped folder at any depth (tests/, fixtures/, vendor/, ...) or under gradle/wrapper/."""
    folders = rel.split("/")[:-1]
    wrapper = tables.gradle_dir.split("/")
    pairs = [folders[i : i + len(wrapper)] for i in range(len(folders))]
    return any(f in tables.dirs for f in folders) or wrapper in pairs


def normalize(path: str, root: str) -> str | None:
    """The repo-relative POSIX form of a path, or None when it names nothing inside the repository."""
    rel = posixpath.normpath(path.replace("\\", "/"))
    for base in (root, os.path.realpath(root)):
        if rel.startswith(base.rstrip("/") + "/"):
            rel = rel[len(base.rstrip("/")) + 1 :]
            break
    return None if rel.startswith(("/", "../")) or rel in {"..", "."} else rel


def _blobs(rel: str, text: str, root: str, event: str) -> tuple[list[Blob], list[Hit]]:
    """Every distinct content this path may take: the working tree, the index at a commit, the pending write."""
    found: list[Blob | None] = []
    hits: list[Hit] = []
    try:
        found.append(read_disk(root, rel))
    except Link as exc:
        hits.append(Hit("symlink-outside", 1, str(exc), None))
    except Unreadable as exc:
        hits.append(Hit("unreadable", 1, str(exc), None))
    if event == "tool_use":
        found.append(from_bytes(text.encode("utf-8", "replace")))
    else:
        found.append(read_git(root, f":./{rel}"))
    distinct = {(blob.sha, blob.head): blob for blob in found if blob is not None}
    return list(distinct.values()), hits


def _content_hits(rel: str, blob: Blob, ctx: tuple[dict[str, str], str, Tables]) -> list[Hit]:
    writes, root, tables = ctx
    hits: list[Hit] = []
    if in_blob_scope(rel, tables):
        name, label = magic(blob.head, rel, tables) or ("", "")
        # A wrapper jar is a zip by nature; the wrapper rule below decides it, any other signature still asks.
        if name and not (is_wrapper_jar(rel) and name.startswith("zip")):
            hits.append(Hit("opaque-magic", 1, f"{label} by its first bytes", blob.sha))
        if high_entropy(blob, tables):
            hits.append(Hit("high-entropy", 1, f"{blob.size} bytes of random-looking data", blob.sha))
    if is_build_text(rel, tables):
        hits += [Hit(f"text-{rule}", line, why, blob.sha) for rule, why, line in text_hits(blob, tables)]
    if is_wrapper_jar(rel) and (why := wrapper_hit(rel, blob, writes, root, tables)):
        hits.append(Hit("gradle-wrapper", 1, why, blob.sha))
    return hits


def judge_path(rel: str, text: str, ctx: tuple[dict[str, str], str, Tables], event: str, allow: Allow) -> list[Hit]:
    """The findings for one path; a content an allowlist entry names (this path and this sha256) is let through."""
    writes, root, tables = ctx
    if not (in_blob_scope(rel, tables) or is_build_text(rel, tables)):
        return []
    blobs, hits = _blobs(rel, text, root, event)
    for blob in blobs:
        if blob.sha is None or (rel, blob.sha) not in allow.entries:
            hits += _content_hits(rel, blob, (writes, root, tables))
    return hits

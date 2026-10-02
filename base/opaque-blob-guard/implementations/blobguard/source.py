"""Bounded reads of one file's bytes: the working tree (never through a symlink) or a git object."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
from collections.abc import Callable
from typing import NamedTuple

from chock_scan.safe_read import FLAGS

HEAD_CAP = 4 << 20
HASH_CAP = 64 << 20
CHUNK = 1 << 16
GIT = shutil.which("git")


class Blob(NamedTuple):
    """What was read: the first HEAD_CAP bytes, the size, and the sha256 (None past HASH_CAP bytes)."""

    head: bytes
    size: int
    sha: str | None


class Unreadable(OSError):  # noqa: N818
    """The file is there and cannot be judged (refused open, not a regular file); the gate asks about it."""


class Link(Exception):  # noqa: N818
    """The path is, or goes through, a symlink that leaves the repository; nothing was read."""


def _digest(read: Callable[[int], bytes], size: int | None) -> Blob:
    """Stream `read` in chunks: keep the head, hash up to HASH_CAP bytes, and never hold more than the head."""
    sha = hashlib.sha256()
    head = bytearray()
    total = 0
    while total < HASH_CAP and (chunk := read(min(CHUNK, HASH_CAP - total))):
        sha.update(chunk)
        total += len(chunk)
        head += chunk[: max(0, HEAD_CAP - len(head))]
    more = total >= HASH_CAP and bool(read(1))
    return Blob(bytes(head), max(size or 0, total + more), None if more else sha.hexdigest())


def from_bytes(data: bytes) -> Blob:
    """A Blob for bytes already in hand (an agent's pending write, encoded as it would land on disk)."""
    return Blob(data[:HEAD_CAP], len(data), hashlib.sha256(data).hexdigest())


def read_disk(root: str, rel: str) -> Blob | None:
    """The working-tree file at root/rel; None when absent or a symlink that stays inside the repository.

    A symlink that leaves the repository (as the final name or through a folder) raises Link; any other
    refusal raises Unreadable. The open uses O_NOFOLLOW, so a name swapped for a link is never followed.
    """
    base = os.path.realpath(root)
    full = os.path.join(base, *rel.split("/"))
    if os.path.commonpath([base, os.path.realpath(os.path.dirname(full))]) != base:
        msg = "a folder on its path is a symlink out of the repository"
        raise Link(msg)
    try:
        if stat.S_ISLNK(os.lstat(full).st_mode):
            if os.path.commonpath([base, os.path.realpath(full)]) != base:
                msg = f"symlink to {os.readlink(full)[:120]!r}, outside the repository"
                raise Link(msg)
            return None
        fd = os.open(full, FLAGS | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        msg = str(exc.strerror or exc)
        raise Unreadable(msg) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            msg = "not a regular file"
            raise Unreadable(msg)
        return _digest(lambda n: os.read(fd, n), info.st_size)
    except OSError as exc:
        msg = str(exc.strerror or exc)
        raise Unreadable(msg) from None
    finally:
        os.close(fd)


def read_git(root: str, spec: str) -> Blob | None:
    """The git object `spec` names (`:./path` for the index, `HEAD:./path`, relative to `root`); None if missing."""
    if GIT is None:
        return None
    try:
        proc = subprocess.Popen(  # noqa: S603 -- the git CLI, a fixed argument vector, no shell
            [GIT, "cat-file", "blob", spec], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except OSError:
        return None
    assert proc.stdout is not None  # noqa: S101 -- PIPE was requested above
    blob = _digest(proc.stdout.read, None)
    if blob.sha is None:
        proc.kill()
    proc.communicate()
    return blob if proc.returncode in (0, -signal.SIGKILL) else None

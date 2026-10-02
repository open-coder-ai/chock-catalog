"""Read a file a gate judges: regular files only, bounded, UTF-8, and explicit about every refusal.

Limit: a regular file is read as it is, so a procfs/sysfs pseudo-file (st_size 0, content made on
read) is read too; gates pass paths from the change being judged, not arbitrary system paths.
"""

from __future__ import annotations

import os
import stat

LIMIT = 1 << 20
MAX_LIMIT = 1 << 26
CHUNK = 1 << 16
BOM = "\ufeff"
NUL = b"\0"
#: Opening a FIFO for reading blocks until a writer appears; O_NONBLOCK makes the open return so
#: fstat can refuse it. O_BINARY and O_NOCTTY exist only where they mean something.
FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)


class UnreadableError(ValueError):
    """The content cannot be judged as text; the caller decides: refuse a security config, report app code."""


def decode(data: bytes, name: str = "<bytes>") -> str:
    """UTF-8 text with one leading BOM removed; a NUL byte or invalid UTF-8 raises UnreadableError."""
    if NUL in data:
        msg = f"{name}: binary (NUL byte at {data.index(NUL)})"
        raise UnreadableError(msg)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        msg = f"{name}: not UTF-8 (byte {exc.start})"
        raise UnreadableError(msg) from None
    return text.removeprefix(BOM)


def read_text(path: str | os.PathLike[str], limit: int = LIMIT) -> str:
    """The text of a regular file of at most `limit` bytes; anything else raises UnreadableError.

    ValueError instead means a caller error: a limit outside 0..MAX_LIMIT, or a path holding NUL.
    """
    if type(limit) is not int or not 0 <= limit <= MAX_LIMIT:
        msg = f"limit must be 0..{MAX_LIMIT}, not {limit}"
        raise ValueError(msg)
    name = os.fsdecode(path)
    try:
        data = _read(path, limit)
    except OSError as exc:
        msg = f"{name}: {exc.strerror or exc}"
        raise UnreadableError(msg) from None
    if data is None:
        msg = f"{name}: not a regular file"
        raise UnreadableError(msg)
    if len(data) > limit:
        msg = f"{name}: larger than {limit} bytes"
        raise UnreadableError(msg)
    return decode(data, name)


def _read(path: str | os.PathLike[str], limit: int) -> bytes | None:
    """At most limit + 1 bytes of a regular file, in chunks; None for anything else."""
    fd = os.open(path, FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks: list[bytes] = []
        size = 0
        while size <= limit and (chunk := os.read(fd, min(CHUNK, limit + 1 - size))):
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)

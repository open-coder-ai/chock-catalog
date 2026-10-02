"""Read a file a gate judges: regular files only, bounded, UTF-8, and explicit about every refusal."""

from __future__ import annotations

import os
import stat

LIMIT = 1 << 20
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
    """The text of a regular file of at most `limit` bytes; anything else raises UnreadableError."""
    if limit < 0:
        msg = f"limit must be 0 or more, not {limit}"
        raise ValueError(msg)
    name = os.fsdecode(path)
    try:
        fd = os.open(path, FLAGS)
    except OSError as exc:
        msg = f"{name}: {exc.strerror or exc}"
        raise UnreadableError(msg) from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        msg = f"{name}: not a regular file"
        raise UnreadableError(msg)
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        msg = f"{name}: larger than {limit} bytes"
        raise UnreadableError(msg)
    return decode(data, name)

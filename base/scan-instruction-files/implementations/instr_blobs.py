"""Encoded blobs in an instruction file: base64 or hex runs of 80+ characters, joined across wrapped lines.

Each blob comes back with its decoded text when it decodes to printable text, so the caller can judge
what it hides. Hex that decodes to binary is a digest or a key fingerprint and is left alone, and so are
a data: URI's payload, a URL's path and a low-entropy or single-case run."""

from __future__ import annotations

import base64
import binascii
import re
from typing import NamedTuple

from chock_scan import entropy

MIN_BLOB = 80
#: A wrapped blob's lines: each one at least this long and nothing but base64 characters.
WRAPPED_LINE = re.compile(r"\s*([A-Za-z0-9+/_-]{40,}={0,2})\s*")
B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{%d,}={0,2}(?![A-Za-z0-9+/_=-])" % MIN_BLOB)
DATA_URI = re.compile(r"(?i)data:[a-z0-9.+/-]*(?:;[a-z0-9=._-]+)*;base64,\s*$")
#: Decoded text must be at least this share printable to be read as text.
PRINTABLE = 0.9
#: How much of the text before a run is read to tell a data: URI or a URL from a blob.
BEFORE = 256
#: Past this many characters a run is judged by its first part only (a decoded megabyte proves nothing more).
MAX_DECODE = 65536


#: Characters that, just before a run, make it part of a URL, path or address rather than a blob.
JOINED = frozenset("./@#?&%")
#: A colon glues a run to what precedes it only after a host (example.com:path), not after a name (KEY:).
HOST_COLON = re.compile(r"[\w-]+\.[\w.-]*:$")


class Blob(NamedTuple):
    """A blob's first and last line, the run as written, and its decoded text (None when not text)."""

    first: int
    last: int
    run: str
    decoded: str | None


def _decoded(run: str) -> str | None:
    """The run's bytes as text when it is valid base64 or hex that decodes to printable text, else None."""
    run = run[:MAX_DECODE]
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", run):
        raw = binascii.unhexlify(run)
    else:
        body = run.rstrip("=").replace("-", "+").replace("_", "/")
        body = body[: len(body) - len(body) % 4] if len(body) % 4 == 1 else body
        try:
            raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
        except (binascii.Error, ValueError):
            return None
    text = raw.decode("utf-8", errors="replace")
    shown = sum((ch.isprintable() and ch != "\ufffd") or ch in "\t\n\r" for ch in text)
    return text if text and shown / len(text) >= PRINTABLE else None


def _runs(lines: list[str]) -> list[tuple[int, int, str, str, bool]]:
    """(first line, last line, run, text before it on its line, whether it is a data: URI payload)."""
    out = []
    n = 0
    carry = False  # a data: URI payload that ran to the end of the previous line continues on this one
    while n < len(lines):
        previous = lines[n - 1] if n else ""
        if WRAPPED_LINE.fullmatch(lines[n]):
            end = n
            while end + 1 < len(lines) and WRAPPED_LINE.fullmatch(lines[end + 1]):
                end += 1
            joined = "".join(line.strip() for line in lines[n : end + 1])
            if end > n and len(joined) >= MIN_BLOB:
                out.append((n + 1, end + 1, joined, "", DATA_URI.search(previous[-BEFORE:]) is not None))
                n = end + 1
                continue
        found, carry = _line_runs(lines[n], n + 1, previous, carry=carry)
        out += found
        n += 1
    return out


def _line_runs(
    line: str, number: int, previous: str, *, carry: bool
) -> tuple[list[tuple[int, int, str, str, bool]], bool]:
    """The base64 runs on one line, and whether a data: URI payload runs on past its end."""
    out, ran_on = [], False
    indent = len(line) - len(line.lstrip())
    for m in B64.finditer(line):
        before = line[max(0, m.start() - BEFORE) : m.start()]
        starts_line = m.start() <= indent
        data = bool(DATA_URI.search(before) or (starts_line and (carry or DATA_URI.search(previous[-BEFORE:]))))
        out.append((number, number, m.group(), before, data))
        ran_on = data and m.end() >= len(line.rstrip())
    return out, ran_on


def _glued(before: str) -> bool:
    """True when a run continues a URL, path, address or host (so it is not a blob of its own)."""
    return before[-1:] in JOINED or HOST_COLON.search(before) is not None


def _opaque(run: str, before: str) -> bool:
    """A run that reads as encoded data: base64 alphabet with mixed case and digits, high entropy, not glued to a URL."""
    if _glued(before) or entropy.charset(run.rstrip("=")) not in {"base64", "base64url", "alnum"}:
        return False
    mixed = re.search(r"[a-z]", run) and re.search(r"[A-Z]", run) and re.search(r"[0-9]", run)
    return bool(mixed) and entropy.shannon(run) >= entropy.THRESHOLDS["base64"]


def blobs(lines: list[str]) -> list[Blob]:
    """Every encoded blob worth judging: one that decodes to text, or an opaque base64 run. Wrapped lines
    that do not decode as one blob (two blobs stacked, a digest beside one) are judged line by line, and
    their joined text, padding removed, as one opaque run."""
    out = []
    for first, last, found, before, data in _runs(lines):
        if data:
            continue
        text = _decoded(found)
        run = found
        if text is None and last > first:
            for number in range(first, last + 1):
                out += _judged(_line_runs(lines[number - 1], number, "", carry=False)[0])
            run = found.replace("=", "")
        out += _judged([(first, last, run, before, False)], text)
    return out


def _judged(runs: list[tuple[int, int, str, str, bool]], text: str | None = None) -> list[Blob]:
    out = []
    for first, last, run, before, _ in runs:
        decoded = text if text is not None else _decoded(run)
        if decoded is not None and not _glued(before):
            out.append(Blob(first, last, run, decoded))
        elif decoded is None and not re.fullmatch(r"[0-9A-Fa-f]+", run) and _opaque(run, before):
            out.append(Blob(first, last, run, None))
    return out

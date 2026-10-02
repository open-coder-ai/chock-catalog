"""What makes a file opaque: a binary or archive signature, high entropy, or text that decodes and evaluates."""

from __future__ import annotations

import posixpath
import re

from blobguard.source import Blob
from blobguard.tables import Sig, Tables
from chock_scan.entropy import shannon

#: Past this many bytes a build text is not pattern-scanned (the patterns are bounded, the gate's clock is not).
TEXT_CAP = 2 << 20
CONTINUATION = re.compile(r"\\\r?\n")
TEXT_CONTROLS = frozenset(b"\t\n\r\f")


def _matches(data: bytes, sig: Sig) -> bool:
    if not all(data[off : off + len(part)] == part for off, part in sig.at):
        return False
    if not sig.non_text_within:
        return True
    return any(b not in TEXT_CONTROLS and (b < 0x20 or b >= 0x80) for b in data[: sig.non_text_within])  # noqa: PLR2004


def magic(data: bytes, rel: str, tables: Tables) -> tuple[str, str] | None:
    """(signature name, label) of the first signature the bytes carry, whatever the file is called."""
    for sig in tables.magic:
        if _matches(data, sig):
            java = sig.name == "cafebabe" and rel.endswith(".class")
            return sig.name, "Java class file" if java else sig.label
    return None


def high_entropy(blob: Blob, tables: Tables) -> bool:
    """A file over the size floor with a window of random-looking bytes; known image and document types are exempt.

    Only the head is sampled, in windows, so a compressed blob behind a text lead-in still shows; the
    exemption is by signature, so media is judged by `magic` alone.
    """
    ent = tables.entropy
    if blob.size <= ent["min_size"] or any(_matches(blob.head, sig) for sig in tables.media):
        return False
    step = ent["window"]
    for start in range(0, len(blob.head), step):
        window = blob.head[start : start + step]
        if len(window) >= min(step, ent["min_tail"]) and shannon(window.decode("latin-1")) >= ent["bits_per_byte"]:
            return True
    return False


def is_build_text(rel: str, tables: Tables) -> bool:
    """configure, configure.ac and *.m4 / *.am at any depth: the files an autotools build evaluates."""
    name = posixpath.basename(rel)
    return name in tables.text_names or name.endswith(tables.text_suffixes)


def text_hits(blob: Blob, tables: Tables) -> list[tuple[str, str, int]]:
    """(rule id, reason, line) for each decode-and-evaluate pattern; a text past TEXT_CAP is one finding."""
    if blob.size > TEXT_CAP:
        return [("text-too-large", f"over {TEXT_CAP} bytes, not scanned", 1)]
    text = CONTINUATION.sub(" ", blob.head.decode("utf-8", "replace"))
    seen: dict[tuple[str, int], str] = {}
    for rule, why, pattern in tables.patterns:
        for found in pattern.finditer(text):
            seen.setdefault((rule, text.count("\n", 0, found.start()) + 1), why)
    return [(rule, why, line) for (rule, line), why in sorted(seen.items(), key=lambda kv: (kv[0][1], kv[0][0]))]

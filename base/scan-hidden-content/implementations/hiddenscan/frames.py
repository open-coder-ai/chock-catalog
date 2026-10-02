"""The records the HTML reader keeps: an open element with the text it hides, and what a file yields."""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from hiddenscan.vocab import visible

KEPT_TEXT = 2000


@dataclass
class Frame:
    tag: str
    line: int
    reason: str | None
    background: str | None
    text: list[str] = field(default_factory=list)
    size: int = 0
    kept: int = 0
    digest: Any = field(default_factory=hashlib.sha256)
    latent: str | None = None  # why it would hide, held back while it sits inside hidden text


@dataclass
class Collected:
    urls: list[tuple[int, str, bool]] = field(default_factory=list)  # (line, URL, fetched without a click)
    hidden: list[tuple[int, str, str, str, str]] = field(default_factory=list)  # (line, tag, reason, shown, key)
    data_html: list[int] = field(default_factory=list)
    hiding_seen: bool = False  # whether any element hid text


def words(data: str) -> str:
    return "".join(unicodedata.normalize("NFKC", visible(data)).casefold().split())


def feed(frame: Frame, data: str, words: str) -> None:
    frame.size += len(words)
    frame.digest.update(words.encode("utf-8", "surrogatepass"))
    if frame.kept < KEPT_TEXT:
        frame.text.append(data[: KEPT_TEXT - frame.kept])
        frame.kept += len(frame.text[-1])

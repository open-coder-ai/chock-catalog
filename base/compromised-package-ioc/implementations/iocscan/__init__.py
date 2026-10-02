"""Readers that list the packages a manifest, lockfile or workflow names, for the compromised-package-ioc gate."""

from __future__ import annotations

from typing import NamedTuple


class Hit(NamedTuple):
    """One package a file names: `version` is an exact version, or None for a range, tag or URL."""

    ecosystem: str
    name: str
    version: str | None
    line: int


class UnparseableError(ValueError):
    """A manifest or lockfile this gate cannot read; the gate refuses it rather than passing it unread."""


def line_of(text: str, needle: str) -> int:
    """The 1-based line of the first occurrence of `needle`, else 1 (display only: keys never hold lines)."""
    at = text.find(needle)
    return text.count("\n", 0, at) + 1 if at >= 0 else 1

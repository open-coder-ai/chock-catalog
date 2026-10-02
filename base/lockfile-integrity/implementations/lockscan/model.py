"""What a lockfile reader yields (one Entry per locked package) and what a rule reports (one Finding)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

BLOCK, ASK = "block", "ask"

UNPARSEABLE = "lock-unparseable"
SOURCE = "lock-source-host"
MISSING = "lock-integrity-missing"
WEAK = "lock-integrity-weak"
CHANGED = "lock-integrity-changed"
UNPINNED = "lock-git-unpinned"
INSTALL = "lock-install-script"
REMOVED = "lock-entries-removed"
LOCK_ONLY = "lock-without-manifest"
MANIFEST_ONLY = "manifest-without-lock"
DELETED = "lock-deleted"
IGNORED = "lock-ignored"
ALLOWLIST_EDIT = "lock-allowlist-edited"
REKEYED = "lock-integrity-rekeyed"
NESTED_ALIAS = "lock-nested-alias"

TIERS = {
    UNPARSEABLE: BLOCK,
    SOURCE: BLOCK,
    MISSING: BLOCK,
    CHANGED: BLOCK,
    UNPINNED: BLOCK,
    ALLOWLIST_EDIT: BLOCK,
    WEAK: ASK,
    INSTALL: ASK,
    REKEYED: ASK,
    NESTED_ALIAS: ASK,
    REMOVED: ASK,
    LOCK_ONLY: ASK,
    MANIFEST_ONLY: ASK,
    DELETED: ASK,
    IGNORED: ASK,
}

#: A full git commit id: what a git source must name to be pinned (40 hex for SHA-1, 64 for SHA-256 repositories).
COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def https(source: str | None) -> bool:
    """Whether a source is absent (the registry default) or an https URL, whatever the scheme's case."""
    return source is None or source[:8].lower() == "https://"


class LockError(ValueError):
    """The lockfile cannot be read with certainty; the gate refuses it rather than judging part of it."""


@dataclass(frozen=True)
class Entry:
    """One locked package as its lockfile records it.

    source: where it is fetched from (a URL or protocol spec) when the lock names one, else None.
    eco: which default registry list `source` is judged against.
    integrity: the hash strings recorded for it, normalised; () when none.
    expect: whether the lock should carry a hash for it (a registry download), so () is a finding.
    weak: the only hash recorded is SHA-1 or weaker.
    git: `source` is a git repository (judged for transport and pin, not against the registry list).
    pinned: for a git source, whether the lock names a full commit id.
    install: the lock marks it as running an install script; transitive: no manifest names it directly.
    tarball: `source` is the package's own npm tarball URL, so on a default registry its path must name it.
    alias: its name comes from an npm: alias only a dependency's lock entry declares, which nothing checks.
    """

    name: str
    version: str
    line: int
    source: str | None = None
    eco: str = ""
    integrity: tuple[str, ...] = ()
    expect: bool = False
    weak: bool = False
    git: bool = False
    pinned: bool = True
    install: bool = False
    transitive: bool = True
    tarball: bool = False
    alias: bool = False

    @property
    def ident(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass(frozen=True)
class Finding:
    rule: str
    key: str
    path: str
    line: int
    message: str

    @property
    def tier(self) -> str:
        return TIERS[self.rule]

    def document(self, *, new: bool) -> dict:
        item = {"key": self.key, "path": self.path, "line": self.line, "message": self.message, "rule": self.rule}
        if new:
            item["new"] = True
        return item


def digest(text: str) -> str:
    """A short fingerprint of text, for keys that must change whenever the text does."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


class Lines:
    """Lines of needles found in document order, in one forward pass over a large text (display only)."""

    def __init__(self, text: str) -> None:
        self.text, self.pos, self.line = text, 0, 1

    def __call__(self, needle: str) -> int:
        """The line of the next `needle` after the last one found; else of its first copy; 1 when absent."""
        pos = self.text.find(needle, self.pos)
        if pos < 0:
            first = self.text.find(needle)
            return self.text.count("\n", 0, first) + 1 if first >= 0 else 1
        self.line += self.text.count("\n", self.pos, pos)
        self.pos = pos
        return self.line


SRI = re.compile(r"(sha1|sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}")
PREFIXED = re.compile(r"(md5|sha1|sha224|sha256|sha384|sha512):[0-9a-fA-F]{32,128}")
WEAK_ALGOS = frozenset({"md5", "sha1"})


def sri(value: object) -> tuple[tuple[str, ...], bool]:
    """(hashes, weak) of an npm-style integrity string: tokens that are not hashes do not count."""
    tokens = [t.split("?", 1)[0] for t in value.split()] if isinstance(value, str) else []
    found = tuple(sorted({t for t in tokens if SRI.fullmatch(t)}))
    return found, bool(found) and all(t.startswith("sha1-") for t in found)


def prefixed(values: list[object]) -> tuple[tuple[str, ...], bool]:
    """(hashes, weak) of 'algo:hex' strings (PyPI, uv, Pipfile, Gemfile.lock); other values do not count."""
    found = tuple(sorted({v.lower() for v in values if isinstance(v, str) and PREFIXED.fullmatch(v)}))
    return found, bool(found) and all(v.split(":", 1)[0] in WEAK_ALGOS for v in found)


def split_spec(spec: str) -> tuple[str, str]:
    """'name@range' (a scope's leading '@' kept in the name) as (name, range); range '' when there is none."""
    at = spec.find("@", 1)
    return (spec, "") if at < 0 else (spec[:at], spec[at + 1 :])

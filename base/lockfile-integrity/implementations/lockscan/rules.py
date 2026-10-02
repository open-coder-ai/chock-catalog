"""The per-lockfile rules: where each package comes from, whether it is pinned and hashed, and what changed."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import PurePosixPath

from chock_scan.hostmatch import Entry as HostEntry

from lockscan import npm, other, pnpm, python, yarn
from lockscan.model import (
    CHANGED,
    INSTALL,
    MISSING,
    REKEYED,
    REMOVED,
    SOURCE,
    UNPARSEABLE,
    UNPINNED,
    WEAK,
    Entry,
    Finding,
    LockError,
    digest,
)
from lockscan.sources import host_of, problem, scheme_of

READERS: dict[str, Callable[[str], list[Entry]]] = {
    "package-lock.json": npm.package_lock,
    "npm-shrinkwrap.json": npm.package_lock,
    "bun.lock": npm.bun_lock,
    "yarn.lock": yarn.yarn_lock,
    "pnpm-lock.yaml": pnpm.pnpm_lock,
    "poetry.lock": python.poetry_lock,
    "uv.lock": python.uv_lock,
    "pipfile.lock": python.pipfile_lock,
    "cargo.lock": other.cargo_lock,
    "go.sum": other.go_sum,
    "gemfile.lock": other.gemfile_lock,
    "gems.locked": other.gemfile_lock,
    "composer.lock": other.composer_lock,
    "packages.lock.json": other.nuget_lock,
}
#: Ecosystems whose lock drops a line for every module it no longer needs, so a removal is worth a look.
REMOVAL_READERS = frozenset({"go.sum"})
#: Ecosystems that record one hash per downloadable file, so a version may gain hashes legitimately.
LOOSE_ECOS = frozenset({"pypi"})


def reader(path: str) -> Callable[[str], list[Entry]] | None:
    """The reader for a lockfile path; names are matched without case, as case-insensitive filesystems open them."""
    return READERS.get(PurePosixPath(path).name.lower())


def read(path: str, text: str) -> tuple[list[Entry] | None, Finding | None]:
    """(entries, None) for a lockfile path, or (None, a refusal) when the lock cannot be read with certainty."""
    read_lock = READERS[PurePosixPath(path).name.lower()]
    try:
        return read_lock(text), None
    except (LockError, RecursionError) as exc:
        reason = exc if isinstance(exc, LockError) else "nested too deeply to read"
        message = f"lockfile cannot be read with certainty ({reason}); fix or regenerate it"
        return None, Finding(UNPARSEABLE, f"{UNPARSEABLE}|{digest(text)}", path, 1, message)


def state_findings(path: str, entries: list[Entry], allow: tuple[HostEntry, ...], note: str) -> list[Finding]:
    """What is wrong with each entry on its own, keyed so a copy already in the baseline cancels it."""
    found = []
    for e in entries:
        if e.source is not None and (
            why := problem(e.source, e.eco, allow, git=e.git, name=e.name if e.tarball else "")
        ):
            where = host_of(e.source) or scheme_of(e.source) or "path"
            extra = f"; {note}" if note else ""
            message = f"{e.ident} is {why}{extra}. Restore the registry URL, or ask a person to add the host"
            found.append(Finding(SOURCE, f"{SOURCE}|{e.ident}|{where}", path, e.line, message))
        if not e.pinned:
            message = f"{e.ident} comes from git without a full commit id: lock it to a commit"
            found.append(Finding(UNPINNED, f"{UNPINNED}|{e.ident}", path, e.line, message))
        if e.expect and not e.integrity:
            message = f"{e.ident} has no integrity hash: regenerate the lock with the package manager"
            found.append(Finding(MISSING, f"{MISSING}|{e.ident}", path, e.line, message))
        elif e.weak:
            message = f"{e.ident} is pinned only by a SHA-1 (or weaker) hash: regenerate the lock for sha512/sha256"
            found.append(Finding(WEAK, f"{WEAK}|{e.ident}", path, e.line, message))
        if e.install and e.transitive:
            message = f"{e.ident} is a transitive package that runs an install script: confirm it is expected"
            found.append(Finding(INSTALL, f"{INSTALL}|{e.ident}", path, e.line, message))
    return found


#: The algorithm (or Berry cache key) a hash was made with; hashes are compared only within one.
ALGO = re.compile(r"(sha1hex|sha1|sha256|sha384|sha512|md5|h1|berry[^/]*)[-:/]")
STRENGTH = {"md5": 0, "sha1": 1, "sha1hex": 1, "sha256": 2, "sha384": 3, "sha512": 4}


def _by_algo(hashes: set[str]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = {}
    for value in hashes:
        found = ALGO.match(value)
        grouped.setdefault(found.group(1) if found else "", set()).add(value)
    return grouped


def _strongest(grouped: dict[str, set[str]]) -> int:
    return max((STRENGTH[algo] for algo in grouped if algo in STRENGTH), default=-1)


def replaced(old: set[str], new: set[str], *, strict: bool) -> bool:
    """Whether the hashes of one package@version changed in a way that admits other content.

    Within one algorithm: any difference when `strict` (an npm client accepts any listed hash of the strongest
    algorithm, so an added one is as good as a replacement), else a hash both removed and added (PyPI lists one
    per file, and a new wheel adds one). Across algorithms: the strongest one dropped (a sha512 replaced by a
    sha1). A new algorithm beside the old ones (a sha1 lock upgraded to sha512) is not a replacement.
    """
    if any("|" in value for value in old | new):
        return _file_replaced(old, new)
    before, after = _by_algo(old), _by_algo(new)
    for algo in before.keys() & after.keys():
        removed, added = before[algo] - after[algo], after[algo] - before[algo]
        if (removed or added) if strict else (removed and added):
            return True
    return bool(new) and 0 <= _strongest(after) < _strongest(before)


def _file_replaced(old: set[str], new: set[str]) -> bool:
    """Per-file hashes ('file|hash', PyPI): a file whose hash changed, in any algorithm, or a file swapped for another.

    A file only added (a newly published wheel) or only removed is not a replacement.
    """
    before: dict[str, set[str]] = {}
    after: dict[str, set[str]] = {}
    for value in old:
        name, _, digest_ = value.partition("|")
        before.setdefault(name, set()).add(digest_)
    for value in new:
        name, _, digest_ = value.partition("|")
        after.setdefault(name, set()).add(digest_)
    if any(before[name] != after[name] for name in before.keys() & after.keys()):
        return True
    return bool(before.keys() - after.keys()) and bool(after.keys() - before.keys())


def _hashes(entries: list[Entry]) -> dict[str, tuple[set[str], int, str]]:
    found: dict[str, tuple[set[str], int, str]] = {}
    for e in entries:
        hashes, _, _ = found.setdefault(e.ident, (set(), e.line, e.eco))
        hashes.update(e.integrity)
    return found


def delta_findings(path: str, entries: list[Entry], base: list[Entry]) -> list[Finding]:
    """Hashes replaced for a package@version the baseline already locked, and (go.sum) modules dropped."""
    found = []
    now, before = _hashes(entries), _hashes(base)
    rekeyed = []
    for ident, (hashes, line, eco) in now.items():
        old = before.get(ident, (set(), 0, eco))[0]
        if replaced(old, hashes, strict=eco not in LOOSE_ECOS):
            message = f"{ident} was already locked with a different hash: the same version must keep its hash"
            found.append(Finding(CHANGED, f"{CHANGED}|{ident}|{digest(' '.join(sorted(hashes)))}", path, line, message))
        elif old and hashes and "|" not in next(iter(hashes)) and not _by_algo(old).keys() & _by_algo(hashes).keys():
            rekeyed.append((ident, line, hashes))
    if rekeyed:
        # every old hash dropped for one under another algorithm or cache key: an upgrade, or a way past the compare
        ident, line, _ = rekeyed[0]
        message = f"{len(rekeyed)} locked version(s) re-hashed under another algorithm or cache key (first: {ident})"
        key = digest(" ".join(f"{i}={sorted(h)}" for i, _, h in rekeyed))
        found.append(Finding(REKEYED, f"{REKEYED}|{key}", path, line, message + ": confirm the upgrade"))
    # go mod tidy drops an old version's lines on every upgrade; a module gone at every version is worth a look
    gone = sorted({e.name for e in base} - {e.name for e in entries})
    if gone and PurePosixPath(path).name.lower() in REMOVAL_READERS:
        message = f"{len(gone)} module(s) removed from go.sum (first: {gone[0]}): confirm they were dropped"
        found.append(Finding(REMOVED, f"{REMOVED}|{digest(' '.join(gone))}", path, 1, message))
    return found

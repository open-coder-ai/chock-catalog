#!/usr/bin/env python3
"""Report each dependency a written manifest names that the allowlist does not list; the engine keeps what a change adds.

Runs as the policy's script gate: stdin is {"event", "repo_root", "writes": {path: text}}; exit 0 allows, 1 refuses, 3 asks,
4 warns (no allowlist exists yet, so a manifest change is allowed with a note), 2 is a fault in this check. It prints a
findings document, one finding per unlisted name keyed by ecosystem and normalised name, and the engine runs it again on
the baseline text and refuses only the keys the change holds more of. `--seed` prints the names the tracked manifests
hold now, for a first allowlist. Manifests are parsed, never run, and no file outside the written set is read, bar the
allowlist (and the tracked files under --seed).
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import subprocess
import sys
from pathlib import Path

# The readers ship beside this script; a missing copy raises, and the runner treats an exit it did not ask for as a refusal.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_scan import safe_read
from depnames import xmlsafe
from depnames.families import REQUIREMENTS, Family, family
from depnames.norm import normalize
from depnames.pyreq import includes

ALLOWLIST = ".chock/dependency-allowlist.txt"
#: Events a person's commit reaches. Any other event, a name never seen included, is an agent's: it reads HEAD's allowlist.
PERSON_EVENTS = frozenset({"commit", "push", "ci"})
GIT = shutil.which("git") or "git"
MAX_CHARS = 16_000_000
ALLOW, ASK, BLOCK, WARN = 0, 3, 1, 4
MAX_LINE_LOOKUPS = 500
MAX_LOOKUP_LINES = 20_000
REFUSALS = {xmlsafe.RefusedError: "declares a DOCTYPE or ENTITY and is not parsed"}
ADVICE = (
    "ask a person to add it, and confirm the package exists in its registry and is the intended one (no lookup is made)"
)
UNSEEDED = (
    "dependency-manifests: {allowlist} does not exist, so the dependencies named in {paths} were not checked. "
    "Allowed with this note. A person seeds the list (`dependency-manifests.py --seed`, then reviews it), commits it, "
    "and from then on an unlisted name is refused."
)


def entries_of(text: str) -> list[str]:
    """Allowlist entries as written; blank lines and `#` comments are dropped."""
    lines = (line.split(" #", 1)[0].strip() for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def git_show(root: Path, *args: str) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(  # noqa: S603 -- read-only git with a fixed argument list
            [GIT, "--no-replace-objects", *args],
            cwd=root,
            capture_output=True,
            timeout=20,
            check=False,
            env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def load_allowlist(root: Path, event: str = "commit") -> list[str] | None:
    """Allowlist entries; an agent's event reads HEAD's file, a person's (commit, push, ci) the file on disk.

    None when the path holds nothing: a repository that has not seeded one, which a plugin-only install cannot do.
    At an agent's event that means nothing at HEAD (a file created since is the agent's), and a file HEAD holds that is
    gone from disk is an empty list. A file that is there but cannot be read is an empty list, so every name is unlisted.
    """
    path = root / ALLOWLIST
    if event not in PERSON_EVENTS and (head := git_show(root, "rev-parse", "--verify", "-q", "HEAD")):
        if head.returncode == 0:
            shown = git_show(root, "show", f"HEAD:./{ALLOWLIST}")
            if shown is None or shown.returncode != 0:
                return None
            if not os.path.lexists(path) or len(shown.stdout) > MAX_CHARS:
                return []
            return entries_of(shown.stdout.decode("utf-8", errors="replace"))
    if not os.path.lexists(path):
        return None
    try:
        return entries_of(safe_read.read_text(path))
    except safe_read.UnreadableError:
        return []


def allowlist_additions(payload: dict, base: list[str] | None) -> list[dict]:
    """One finding per entry an agent's write puts in the allowlist that the list in force does not hold."""
    text = written(payload).get(ALLOWLIST)
    known = {entry.lower() for entry in base or []}
    found: dict[str, dict] = {}
    for number, line in enumerate((text or "").splitlines(), 1):
        name = next(iter(entries_of(line)), "")
        if name and name.lower() not in known:
            message = f"{name} is added to {ALLOWLIST} by a write; only a person extends the allowlist"
            key = f"allowlist|{name.lower()}"
            found.setdefault(key, {"key": key, "path": ALLOWLIST, "line": number, "message": message})
    return list(found.values())


class Allowed:
    """The allowlist as each ecosystem spells its names: one set per ecosystem, normalised once."""

    def __init__(self, entries: list[str]) -> None:
        self.entries = entries
        self.by_eco: dict[str, set[str]] = {}

    def __contains__(self, item: tuple[str, str]) -> bool:
        eco, name = item
        if eco not in self.by_eco:
            self.by_eco[eco] = {normalize(eco, entry) for entry in self.entries}
        return name in self.by_eco[eco]


class TooLargeError(ValueError):
    """The text is larger than this gate reads."""


def read_names(fam: Family, text: str) -> list[str]:
    """Distinct normalised names of one manifest; the reader's errors are left to the caller."""
    if len(text) > MAX_CHARS:
        msg = "larger than the size this gate reads"
        raise TooLargeError(msg)
    if "\0" in text:
        msg = "binary, or UTF-16/UTF-32 text, which pip reads by its BOM and this gate cannot"
        raise safe_read.UnreadableError(msg)
    return sorted({normalize(fam.eco, name) for name in fam.read(text) if name.strip()})


def line_of(lines: list[str], name: str) -> int:
    """The first of the lowercased lines mentioning the name, for display; 1 when none does."""
    needle = name.lower()
    return next((n for n, line in enumerate(lines, 1) if needle in line), 1)


def targets(writes: dict[str, str]) -> dict[str, Family]:
    """Written paths to judge: every manifest by name, plus files a written requirements file includes in-repo."""
    found = {path: fam for path in writes if "node_modules" not in path.split("/") and (fam := family(path))}
    queue = [path for path, fam in found.items() if fam is REQUIREMENTS]
    while queue:
        path = queue.pop()
        wanted = includes(writes[path]) if len(writes[path]) <= MAX_CHARS else []
        for target in wanted:
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
            if resolved.startswith(("..", "/")) or resolved in found or resolved not in writes:
                continue
            found[resolved] = REQUIREMENTS
            queue.append(resolved)
    return found


def covers(manifest_dir: str, lock_dir: str) -> bool:
    """Whether a manifest in `manifest_dir` is one the lockfile in `lock_dir` pins (the same folder, or a workspace below)."""
    return lock_dir in ("", manifest_dir) or manifest_dir.startswith(lock_dir + "/")


def written(payload: dict) -> dict[str, str]:
    """The change's files by POSIX path."""
    return {path.replace("\\", "/"): text for path, text in payload.get("writes", {}).items()}


def unseeded(payload: dict) -> int:
    """No allowlist exists: a change to a manifest or lockfile is allowed with a note naming it; any other change is silent."""
    found = sorted(targets(written(payload)))
    if not found:
        return ALLOW
    print(UNSEEDED.format(allowlist=ALLOWLIST, paths=", ".join(found)), file=sys.stderr)
    return WARN


def judge(payload: dict, allowed: Allowed) -> tuple[list[dict], list[dict]]:
    """(block findings, ask findings): a lockfile name or a manifest that cannot be parsed asks.

    A lockfile name is asked about only when no manifest of its ecosystem changed beside it: with one, the manifest's
    names are the judgement and the lock's transitive names are what installing them brings.
    """
    manifest: list[dict] = []
    locks: list[dict] = []
    writes = written(payload)
    found = targets(writes)
    manifest_dirs = [(fam.eco, posixpath.dirname(path)) for path, fam in found.items() if not fam.lock]
    for path, fam in sorted(found.items()):
        text = writes[path]
        try:
            names = read_names(fam, text)
        except (xmlsafe.RefusedError, TooLargeError, RecursionError, MemoryError) as exc:
            why = REFUSALS.get(type(exc), "is too large or too deeply nested to read")
            digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]
            message = f"{fam.kind} {why}, so its dependencies cannot be checked"
            (locks if fam.lock else manifest).append(
                {"key": f"refused|{type(exc).__name__}|{digest}", "path": path, "line": 1, "message": message}
            )
            continue
        except Exception as exc:  # noqa: BLE001 -- untrusted manifest text; a file the reader cannot parse is not a pass
            digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]
            message = f"{fam.kind} could not be parsed ({type(exc).__name__}), so its dependencies were not checked"
            locks.append(
                {"key": f"unreadable|{type(exc).__name__}|{digest}", "path": path, "line": 1, "message": message}
            )
            continue
        if fam.lock and any(eco == fam.eco and covers(each, posixpath.dirname(path)) for eco, each in manifest_dirs):
            continue
        findable = not fam.lock and len(names) <= MAX_LINE_LOOKUPS and text.count("\n") <= MAX_LOOKUP_LINES
        lines = text.lower().splitlines() if findable else []
        for name in names:
            if (fam.eco, name) in allowed:
                continue
            where = "pinned in the lockfile" if fam.lock else f"added to {fam.kind}"
            message = f"{name} is {where} and is not in {ALLOWLIST}; {ADVICE}"
            (locks if fam.lock else manifest).append(
                {"key": f"{fam.eco}|{name}", "path": path, "line": line_of(lines, name), "message": message}
            )
    return manifest, locks


def seed(root: Path) -> int:
    """Print the distinct names the tracked manifests hold, one per line, as a first allowlist."""
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout  # noqa: S607
    names: set[str] = set()
    for raw in tracked.split(b"\0"):
        path = raw.decode("utf-8", errors="replace")
        fam = family(path) if path else None
        if fam is None or fam.lock:
            continue
        try:
            names.update(read_names(fam, safe_read.read_text(root / path)))
        except Exception as exc:  # noqa: BLE001 -- one unreadable manifest must not stop the seed
            print(f"dependency-manifests: {path} skipped ({type(exc).__name__})", file=sys.stderr)
    print("# Seeded from the tracked manifests; review before committing.")
    print("\n".join(sorted(names)))
    return 0


def main() -> int:
    if sys.argv[1:] == ["--seed"]:
        return seed(Path.cwd())
    try:
        payload = json.load(sys.stdin)
        event = payload.get("event", "")
        entries = load_allowlist(Path(payload["repo_root"]), event)
        added = [] if event in PERSON_EVENTS else allowlist_additions(payload, entries)
        if entries is None and not added:
            return unseeded(payload)
        manifest, locks = judge(payload, Allowed(entries)) if entries is not None else ([], [])
        manifest = added + manifest
    except Exception as exc:  # noqa: BLE001 -- a fault must not read as a verdict
        print(f"dependency-manifests: internal error ({type(exc).__name__}); manifests not checked", file=sys.stderr)
        return 2
    print(json.dumps({"findings": manifest + locks}))
    found = manifest or locks
    if not found:
        return 0
    kind = (
        "Unlisted dependency refused"
        if manifest
        else "Unlisted lockfile package, or a manifest that could not be parsed"
    )
    print(f"dependency-manifests: {kind}:", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        f"Names are checked against {ALLOWLIST}; this gate makes no registry lookup, so confirm the package exists in its "
        "registry and is the intended one. Ask a person to add the name; do not edit the allowlist yourself.",
        file=sys.stderr,
    )
    return BLOCK if manifest else ASK


if __name__ == "__main__":
    sys.exit(main())

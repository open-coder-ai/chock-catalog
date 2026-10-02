#!/usr/bin/env python3
"""Report each dependency a written manifest names that the allowlist does not list; the engine keeps what a change adds.

Runs as the policy's script gate: stdin is {"event", "repo_root", "writes": {path: text}}; exit 0 allows, 1 refuses, 3 asks,
2 is a fault in this check. It prints a findings document, one finding per unlisted name keyed by ecosystem and normalised
name, and the engine runs it again on the baseline text and refuses only the keys the change holds more of. `--seed`
prints the names the tracked manifests hold now, for a first allowlist. Manifests are parsed, never run, and no file
outside the written set is read.
"""

from __future__ import annotations

import json
import posixpath
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
MAX_CHARS = 2_000_000
ASK, BLOCK = 3, 1
ADVICE = (
    "ask a person to add it, and confirm the package exists in its registry and is the intended one (no lookup is made)"
)


def load_allowlist(root: Path) -> list[str]:
    """Allowlist entries, lowercased; blank lines and `#` comments are dropped, and a missing file is an empty list."""
    try:
        text = safe_read.read_text(root / ALLOWLIST)
    except safe_read.UnreadableError:
        return []
    lines = (line.split(" #", 1)[0].strip().lower() for line in text.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


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


def read_names(fam: Family, text: str) -> list[str]:
    """Distinct normalised names of one manifest; the reader's errors are left to the caller."""
    if len(text) > MAX_CHARS:
        msg = "larger than the size this gate reads"
        raise ValueError(msg)
    return sorted({normalize(fam.eco, name) for name in fam.read(text) if name.strip()})


def line_of(text: str, name: str) -> int:
    """The first line mentioning the name, for display; 1 when none does."""
    needle = name.lower()
    return next((n for n, line in enumerate(text.splitlines(), 1) if needle in line.lower()), 1)


def targets(writes: dict[str, str]) -> dict[str, Family]:
    """Written paths to judge: every manifest by name, plus files a written requirements file includes in-repo."""
    found = {path: fam for path in writes if (fam := family(path))}
    queue = [path for path, fam in found.items() if fam is REQUIREMENTS]
    while queue:
        path = queue.pop()
        wanted = includes(writes[path])
        for target in wanted:
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
            if resolved.startswith(("..", "/")) or resolved in found or resolved not in writes:
                continue
            found[resolved] = REQUIREMENTS
            queue.append(resolved)
    return found


def judge(payload: dict, allowed: Allowed) -> tuple[list[dict], list[dict], list[str]]:
    """(manifest findings, lockfile findings, notes about files that could not be read)."""
    manifest: list[dict] = []
    locks: list[dict] = []
    notes: list[str] = []
    writes = {path.replace("\\", "/"): text for path, text in payload.get("writes", {}).items()}
    for path, fam in sorted(targets(writes).items()):
        text = writes[path]
        try:
            names = read_names(fam, text)
        except xmlsafe.RefusedError:
            message = (
                f"{fam.kind} declares a DOCTYPE or ENTITY, so it is not parsed and its dependencies cannot be checked"
            )
            manifest.append({"key": "refused|doctype", "path": path, "line": 1, "message": message})
            continue
        except Exception as exc:  # noqa: BLE001 -- untrusted manifest text; an unreadable file contributes no names
            notes.append(
                f"{path}: could not be read as {fam.kind} ({type(exc).__name__}); its dependencies were not checked"
            )
            continue
        for name in names:
            if (fam.eco, name) in allowed:
                continue
            where = "pinned in the lockfile" if fam.lock else f"added to {fam.kind}"
            message = f"{name} is {where} and is not in {ALLOWLIST}; {ADVICE}"
            (locks if fam.lock else manifest).append(
                {"key": f"{fam.eco}|{name}", "path": path, "line": line_of(text, name), "message": message}
            )
    return manifest, locks, notes


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
        manifest, locks, notes = judge(payload, Allowed(load_allowlist(Path(payload["repo_root"]))))
    except Exception as exc:  # noqa: BLE001 -- a fault must not read as a verdict
        print(f"dependency-manifests: internal error ({type(exc).__name__}); manifests not checked", file=sys.stderr)
        return 2
    print(json.dumps({"findings": manifest + locks}))
    if not payload.get("baseline"):
        for note in notes:
            print(f"dependency-manifests: {note}", file=sys.stderr)
    found = manifest or locks
    if not found:
        return 0
    kind = "Unlisted dependency refused" if manifest else "Unlisted package in a lockfile"
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

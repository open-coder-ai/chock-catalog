#!/usr/bin/env python3
"""Report what a change does to lockfiles that signals tampering or lost provenance; the change's own findings only.

Runs as the policy's script gate: stdin is {"event", "repo_root", "writes": {path: text}} (plus "baseline": true on
the engine's second run); exit 0 allows, 1 refuses, 3 asks, 2 is a fault in this check. At a commit and at agent
tool use the gate reads the baseline itself (HEAD at a commit; at tool use the file on disk, or HEAD when the disk
already holds the write) so it can compare a package@version across both, and it marks every finding new. At push
and in CI it cannot name the range base, so it reports per-file findings keyed for the engine's baseline run. At push
and in CI the host allowlist is the one at the range base (the pull request's base branch, the commit a push started
from, else the first parent), never the one the change under judgement carries; a base that cannot be named is a fault.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

# The rules ship beside this script. A missing or broken copy raises here, and the runner treats an exit
# it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lockscan.model import ALLOWLIST_EDIT, BLOCK, Finding, digest
from lockscan.rules import delta_findings, read, reader, state_findings
from lockscan.sources import ALLOWLIST, load_allowlist
from lockscan.sync import deleted_findings, ignore_findings, sync_findings

GIT = shutil.which("git")
SELF_BASELINE = frozenset({"commit", "agent-commit", "tool_use"})
#: Events that judge a whole change, where a lock and its manifest are expected to move together.
CHANGE_EVENTS = frozenset({"commit", "agent-commit", "push", "ci"})
COMMIT_EVENTS = frozenset({"commit", "agent-commit"})
#: Events where the agent is the writer: it may not widen the host allowlist that judges its own locks.
AGENT_EVENTS = frozenset({"agent-commit", "tool_use"})
#: Events where the allowlist is not the change's to edit: an agent's, and CI, which judges a change of any author.
EDIT_EVENTS = AGENT_EVENTS | {"ci"}
#: Events judged against a range: the allowlist is read at its base.
RANGE_EVENTS = frozenset({"push", "ci"})
EVENT_LIMIT = 1 << 20
SHA = re.compile(r"[0-9a-f]{40}")
BASE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
ALLOW, REFUSE, FAULT, ASK = 0, 1, 2, 3


class BaseError(RuntimeError):
    """The base of the range under judgement cannot be named, so the allowlist that judges it cannot be read."""


def git(root: Path, *args: str) -> str | None:
    """git's stdout, or None when git is absent or fails (no HEAD, no repository, path not in HEAD)."""
    if GIT is None:
        return None
    proc = subprocess.run(  # noqa: S603 -- a fixed git read in the repository under judgement
        [GIT, "-c", "core.quotePath=false", *args], cwd=root, capture_output=True, check=False
    )
    return proc.stdout.decode("utf-8", errors="replace") if proc.returncode == 0 else None


def committed(root: Path, path: str) -> str | None:
    """The file as HEAD has it; None for a path outside the repository or not in HEAD."""
    return None if PurePosixPath(path).is_absolute() else git(root, "show", f"HEAD:./{path}")


def resolves(root: Path, ref: str) -> bool:
    return git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}") is not None


def parent_exists(root: Path) -> bool:
    return resolves(root, "HEAD^1")


def is_shallow(root: Path) -> bool:
    return (git(root, "rev-parse", "--is-shallow-repository") or "").strip() == "true"


def pushed_before() -> str:
    """The commit a push started from, read from the CI's event file; empty when there is none."""
    try:
        with Path(os.environ.get("GITHUB_EVENT_PATH", "")).open(encoding="utf-8") as handle:
            before = json.loads(handle.read(EVENT_LIMIT)).get("before")
    except (OSError, ValueError, AttributeError):
        return ""
    return before if isinstance(before, str) and SHA.fullmatch(before) and set(before) != {"0"} else ""


def range_base(root: Path) -> str | None:
    """The ref the change under judgement started from: the pull request's base, the pushed `before`, else the first
    parent. None for a root commit; BaseError when the CI names a base git cannot resolve or the history is cut."""
    name = os.environ.get("GITHUB_BASE_REF", "").strip()
    if name:
        ref = f"origin/{name}"
        if not BASE_REF.fullmatch(name) or not resolves(root, ref):
            msg = f"base ref {ref!r} does not resolve; fetch it (actions/checkout fetch-depth: 0)"
            raise BaseError(msg)
        return ref
    before = pushed_before()
    if before and resolves(root, before):
        head = (git(root, "rev-parse", "HEAD") or "").strip()
        if (git(root, "rev-parse", before) or "").strip() != head:
            return before
    if parent_exists(root):
        return "HEAD^1"
    if is_shallow(root):
        msg = "a shallow checkout has no parent to compare with; fetch more history (actions/checkout fetch-depth: 0)"
        raise BaseError(msg)
    return None


def registry_allowlist(root: Path, event: str) -> str | None:
    """The allowlist text that judges this event: at the range base for push and CI, else as HEAD holds it."""
    if event not in RANGE_EVENTS:
        return committed(root, ALLOWLIST)
    base = range_base(root)
    return None if base is None else git(root, "show", f"{base}:./{ALLOWLIST}")


def baseline_text(root: Path, event: str, path: str, written: str) -> str | None:
    """The file before the change, as the engine reads it: HEAD at a commit; at tool use the disk, unless the
    disk already holds the write (the turn's end), then HEAD."""
    if event == "tool_use":
        disk = Path(path) if PurePosixPath(path).is_absolute() else root / path
        try:
            text = disk.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            text = None
        if text is not None and text != written:
            return text
    return committed(root, path)


class Judge:
    """Findings for one world of files (the change, or its baseline), with each lock read once."""

    def __init__(self, root: Path, event: str, allow: tuple, note: str) -> None:
        self.root, self.event, self.allow, self.note = root, event, allow, note

    def world(self, files: dict[str, str]) -> tuple[list[Finding], dict[str, list]]:
        found: list[Finding] = []
        parsed: dict[str, list] = {}
        for path, text in files.items():
            if reader(path) is None:
                continue
            entries, refusal = read(path, text)
            if refusal:
                found.append(refusal)
            else:
                parsed[path] = entries
                found += state_findings(path, entries, self.allow, self.note)
        if self.event in CHANGE_EVENTS:
            found += sync_findings(files, self.root)
        if self.event in EDIT_EVENTS:
            found += [allowlist_edit(path, text) for path, text in files.items() if is_allowlist(path)]
        return found + ignore_findings(files, self.root), parsed


def is_allowlist(path: str) -> bool:
    """The allowlist under any spelling of its path: case, `./`, `//` and surrounding blanks do not hide it."""
    norm = posixpath.normpath(path.strip()).lower()
    return norm == ALLOWLIST or norm.endswith("/" + ALLOWLIST)


def allowlist_edit(path: str, text: str) -> Finding:
    message = f"{ALLOWLIST} may not be edited by an agent or in the change under review: a person reviews a registry host and commits it on its own"
    return Finding(ALLOWLIST_EDIT, f"{ALLOWLIST_EDIT}|{digest(text)}", path, 1, message)


def subtract(found: list[Finding], base: list[Finding]) -> list[Finding]:
    """The findings the baseline does not account for: per path and key, each baseline copy absolves one."""
    unspent = Counter((f.path, f.key) for f in base)
    fresh = []
    for item in found:
        if unspent[(item.path, item.key)]:
            unspent[(item.path, item.key)] -= 1
        else:
            fresh.append(item)
    return fresh


def judge(payload: dict) -> tuple[list[Finding], bool]:
    """(findings, already compared with the baseline)."""
    writes = payload.get("writes")
    if not isinstance(writes, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in writes.items()):
        msg = "payload has no writes object"
        raise TypeError(msg)
    writes = {path.replace("\\", "/"): text for path, text in writes.items()}
    root = Path(str(payload.get("repo_root") or "."))
    event = str(payload.get("event", ""))
    if payload.get("baseline") is True and event in SELF_BASELINE:
        return [], False  # the change-run already compared with the baseline and marked its findings new
    allow, note = load_allowlist(registry_allowlist(root, event))
    rules = Judge(root, event, allow, note)
    found, parsed = rules.world(writes)
    if payload.get("baseline") is True or event not in SELF_BASELINE:
        return found, False
    befores = {path: baseline_text(root, event, path, text) for path, text in writes.items()}
    base_files = {path: text for path, text in befores.items() if text is not None}
    base_found, base_parsed = rules.world(base_files)
    fresh = subtract(found, base_found)
    for path, entries in parsed.items():
        if path in base_parsed:
            fresh += delta_findings(path, entries, base_parsed[path])
    if event in COMMIT_EVENTS:
        deleted = git(root, "diff", "--cached", "--name-only", "--diff-filter=D", "-z") or ""
        fresh += deleted_findings([p for p in deleted.split("\0") if p], root)
    return fresh, True


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        found, compared = judge(payload)
    except Exception as exc:  # noqa: BLE001 -- a fault must not read as a verdict
        print(f"lockfile-integrity-gate: internal error ({type(exc).__name__}); lockfiles not checked", file=sys.stderr)
        return FAULT
    print(json.dumps({"findings": [f.document(new=compared) for f in found]}))
    if payload.get("baseline") is True or not found:
        return ALLOW
    print("lockfile-integrity: lockfile change refused or held for a person:", file=sys.stderr)
    for item in found:
        print(f"  {item.path}:{item.line}: [{item.rule}] {item.message}", file=sys.stderr)
    return REFUSE if any(f.tier == BLOCK for f in found) else ASK


if __name__ == "__main__":
    sys.exit(main())

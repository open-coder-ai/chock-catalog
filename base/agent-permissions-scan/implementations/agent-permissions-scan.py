#!/usr/bin/env python3
"""Report what a written agent permission config grants beyond named, scoped actions; the engine keeps what a change adds.

Runs as the policy's script gate: stdin is {"event", "repo_root", "writes": {path: text}} (and "baseline": true on the
engine's second run over the HEAD text); exit 0 allows, 1 refuses, 2 is a fault in this check. It prints a findings
document keyed by rule, key path (no list indexes) and normalized value, so a reorder or reformat is not new.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import posixpath
import sys
from collections import Counter
from pathlib import Path

# The rules ship beside this script. A missing or broken copy raises here, and the runner treats an
# exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_scan import safe_read
from perms import load, rules, sidecar, walk

ALLOW, REFUSE, FAULT = 0, 1, 2
#: Where a person reviews what is committed or pushed; anywhere else a waiver counts only once committed.
HUMAN_EVENTS = frozenset({"commit"})
AGENT_ENV = ("CHOCK_AGENT_COMMIT", "CLAUDECODE", "AI_AGENT")
FALSY = frozenset({"", "0", "false", "no", "off"})


def by_person(event: str) -> bool:
    agent = any(os.environ.get(name, "").strip().lower() not in FALSY for name in AGENT_ENV)
    return event in HUMAN_EVENTS and not agent


def line_of(text: str, *needles: str) -> int:
    """The first line holding a needle, 1-based; 1 when none does."""
    for needle in needles:
        at = text.find(needle) if needle else -1
        if at >= 0:
            return text.count("\n", 0, at) + 1
    return 1


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def repo_path(root: Path, path: str) -> str:
    """The path as the repository names it: `/` separators, no leading `./`, an absolute path under `root` made relative."""
    name = posixpath.normpath(path.replace("\\", "/"))
    if Path(name).is_absolute():
        with contextlib.suppress(ValueError):
            name = Path(name).relative_to(root.resolve()).as_posix()
    return name


def current_waivers(root: Path, writes: dict[str, str], *, person: bool) -> frozenset:
    """Waivers from HEAD; a person's own change to the sidecar counts too. A sidecar that breaks the schema gives none."""
    staged = writes.get(sidecar.PATH)
    text = staged if person and staged is not None else sidecar.committed(root, sidecar.PATH)
    try:
        return sidecar.waivers(text) if text is not None else frozenset()
    except sidecar.SidecarError:
        return frozenset()


def before_denies(root: Path, path: str, kind: str, surface: str, event: str) -> Counter:
    """Deny entries the file held at HEAD, and on disk before a tool-use write; unreadable text adds none."""
    texts: list[str | None] = [*sidecar.committed_all(root, path)]
    if event == "tool_use" and ".." not in path.split("/"):
        with contextlib.suppress(safe_read.UnreadableError, ValueError):
            texts.append(safe_read.read_text(root / path))
    held: Counter = Counter()
    for text in texts:
        try:
            held |= walk.denies(load.parse(kind, text).tree, surface) if text is not None else Counter()
        except load.UnreadableError:
            continue
    return held


def file_findings(path: str, text: str, root: Path, event: str, *, baseline: bool) -> list[tuple[walk.Hit, int, bool]]:
    """(hit, line, always new) for one config; an unreadable one is a single hit keyed by a digest of its text."""
    kind, surface = load.classify(path)
    try:
        parsed = load.parse(kind, text)
    except load.UnreadableError as exc:
        why = f"cannot be read ({exc}), so what it grants cannot be judged"
        return [(walk.Hit("ap-unreadable", "<file>", digest(text), why), 1, False)]
    found = [
        (hit, line_of(text, hit.value, hit.path.rsplit(".", 1)[-1]), False)
        for hit in walk.hits(*_args(parsed, surface))
    ]
    if not baseline:
        gone = before_denies(root, path, kind, surface, event) - walk.denies(parsed.tree, surface)
        found += [
            (walk.Hit(walk.DENY, where, entry, "a deny entry the base held is gone"), 1, True) for where, entry in gone
        ]
    return found


def _args(parsed: load.Parsed, surface: str) -> tuple:
    return parsed.tree, surface, parsed.hidden


def findings(payload: dict) -> list[dict]:
    event = str(payload.get("event", ""))
    root = Path(str(payload.get("repo_root") or ".")).resolve()
    baseline = bool(payload.get("baseline"))
    rules.start_budget()
    writes = {
        repo_path(root, path): text for path, text in (payload.get("writes") or {}).items() if isinstance(text, str)
    }
    person = by_person(event)
    waived = current_waivers(root, writes, person=person)
    found = []
    for name, text in sorted(writes.items()):
        if name.casefold() == sidecar.PATH:
            found += _sidecar_finding(name, text, root, person=person or baseline)
        if load.classify(name) is None:
            continue
        if name.startswith(("/", "../")) or name == "..":
            found.append(_unmapped(name))
        for hit, line, new in file_findings(name, text, root, event, baseline=baseline):
            if (name, hit.path, hit.value) in waived:
                continue
            item = {"key": f"{hit.rule}|{hit.path}|{hit.value}", "path": name, "line": line}
            found.append({**item, "message": f"[{hit.rule}] {hit.why}: {hit.path} = {hit.value}", "new": new})
    return found


def _unmapped(name: str) -> dict:
    message = f"[ap-unmapped] {name} is outside the repository, so its HEAD copy cannot be compared"
    return {"key": f"ap-unmapped|{digest(name)}", "path": name, "line": 1, "message": message}


def _sidecar_finding(name: str, text: str, root: Path, *, person: bool) -> list[dict]:
    """The sidecar's own findings: a schema break, and (unless a person writes it) each waiver the change adds."""
    try:
        added = sidecar.waivers(text)
    except sidecar.SidecarError as exc:
        message = f"[ap-sidecar-invalid] {sidecar.PATH} breaks its closed schema ({exc}); no waiver in it counts"
        return [{"key": f"ap-sidecar-invalid|{digest(text)}", "path": name, "line": 1, "message": message}]
    if person:
        return []
    with contextlib.suppress(sidecar.SidecarError):
        added -= sidecar.waivers(sidecar.committed(root, sidecar.PATH) or "")
    return [
        {
            "key": f"ap-agent-waiver|{'|'.join(waiver)}",
            "path": name,
            "line": 1,
            "message": f"[ap-agent-waiver] a waiver for {waiver[0]} {waiver[1]} = {waiver[2]} is added outside a person's commit",
            "new": True,
        }
        for waiver in sorted(added)
    ]


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        found = findings(payload)
    except Exception as exc:  # noqa: BLE001 -- anything unexpected is undecided, which the runner refuses
        print(
            f"agent-permissions-scan could not reach a decision ({type(exc).__name__}); configs not checked",
            file=sys.stderr,
        )
        return FAULT
    print(json.dumps({"findings": found}))
    if not found:
        return ALLOW
    print("agent-permissions-scan: an agent permission config grants more than named, scoped actions:", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        "Scope each grant to named tools or commands (Bash(npm test:*)), keep every deny entry, and leave modes that "
        f"ask. A reviewed exception is a {{file, path, value}} entry under `waive` in {sidecar.PATH}, added by a "
        "person in their own commit; an agent asks the person and never writes it.",
        file=sys.stderr,
    )
    return REFUSE


if __name__ == "__main__":
    sys.exit(main())

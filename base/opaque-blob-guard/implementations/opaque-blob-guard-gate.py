#!/usr/bin/env python3
"""Report opaque binaries, archives and decode-and-evaluate build text in test, fixture and vendor paths."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# The detectors and the lib/ copies ship beside this script. A missing or broken copy raises here, and
# the runner treats an exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from blobguard import allow, judge, tables
from chock_scan.data_table import TableError

ASK = 3


def findings(payload: dict) -> list[dict]:
    """Every opaque file in the change, keyed by rule and content hash so a moved file is the same finding.

    A baseline run is answered with nothing: the baseline text of a binary is lossy, so every finding
    counts as new, which errs toward asking.
    """
    if payload.get("baseline"):
        return []
    table = tables.load()
    root = str(payload.get("repo_root") or ".")
    event = str(payload.get("event", ""))
    raw = payload.get("writes")
    writes = {
        k: v for k, v in (raw if isinstance(raw, dict) else {}).items() if isinstance(k, str) and isinstance(v, str)
    }
    clean = {rel: text for path, text in writes.items() if (rel := judge.normalize(path, root)) is not None}
    approved = allow.load(root, table, committed_only=event in judge.AGENT_EVENTS)
    note = f" (allowlist ignored: {approved.problem})" if approved.problem else ""
    found = []
    if approved.problem and table.allowlist in clean:
        found.append(
            _row(
                "allowlist-malformed",
                table.allowlist,
                1,
                f"{approved.problem}; every blob is asked about",
                approved.problem,
            )
        )
    for rel, text in sorted(clean.items()):
        for hit in judge.judge_path(rel, text, (clean, root, table), event, approved):
            found.append(_row(hit.rule, rel, hit.line, hit.message + note, f"{hit.sha or hit.message}"))
    return found


def _row(rule: str, path: str, line: int, message: str, ident: str) -> dict:
    """One finding; the key is the rule and the content hash (or the reason), never a line number."""
    return {"key": f"{rule}|{ident[:64]}", "path": path, "line": line, "rule": rule, "message": message[:300]}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("opaque-blob-guard: stdin is not the gate JSON", file=sys.stderr)
        return 2
    try:
        found = findings(payload if isinstance(payload, dict) else {})
    except TableError as exc:
        print(f"opaque-blob-guard: a data table is unusable, nothing was judged: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print("opaque-blob-guard: opaque content in a path where a reviewer cannot read it (would ask):", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        "State why the file is needed and list it as '<sha256>  <path>' in .chock/blob-allowlist.txt, committed "
        "by a person; or generate it in the test setup, or fetch it from a pinned, checksummed source. An "
        "agent asks a person: an allowlist entry written in the same agent change does not count.",
        file=sys.stderr,
    )
    return ASK


if __name__ == "__main__":
    sys.exit(main())

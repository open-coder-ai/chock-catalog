#!/usr/bin/env python3
"""Report each changed path whose name a shell, a CI step or git can misread.

Runs as the policy's script gate: stdin is {"event", "repo_root", "writes": {path: text}}; exit 0 allows, 1 refuses,
2 is a fault in this check (the engine refuses then too). It prints a findings document keyed by the path, and the
engine runs it again on the baseline text, which holds only paths that already existed, so a path the change adds or
renames into is judged and one already tracked never blocks an edit to it. git quotes a path holding a control
character, a double quote or a backslash ("a\\nb"); a quoted path is refused as such. The engine trims the names
it lists, so at a commit this gate also asks git for the added and renamed names NUL-separated, and judges one
with a leading or trailing space as new.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from refname_rules import ADVICE, describe, problems, shown

QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
QUOTED_REASON = "a control character, a double quote or a backslash (git prints it quoted)"
COMMIT_EVENTS = ("commit", "agent-commit")
GIT = shutil.which("git") or "git"


def judge(path: str) -> list[tuple[str, str]]:
    """Every reason the path is refused; empty when it is plain."""
    if QUOTED.fullmatch(path):
        return [("quoted", QUOTED_REASON)]
    return problems(path)


def padded_names(payload: dict) -> list[str]:
    """At a commit, the added or renamed names that start or end in whitespace, which the engine's list trims."""
    if payload.get("event") not in COMMIT_EVENTS or payload.get("baseline"):
        return []
    listing = subprocess.run(  # noqa: S603 -- read-only: the staged names, as git stores them
        [GIT, "diff", "--cached", "--name-only", "-z", "--diff-filter=AR"],
        cwd=payload.get("repo_root") or ".",
        capture_output=True,
        check=True,
    )
    names = listing.stdout.decode("utf-8", errors="replace").split("\0")
    return [name for name in names if name != name.strip()]


def _finding(path: str, reasons: list[tuple[str, str]], **extra: bool) -> dict:
    safe = shown(path)
    message = describe("file name", path, reasons).removesuffix(f" {ADVICE}")
    return {"key": f"name|{safe}", "path": safe, "line": 1, "message": message, "rule": "filename", **extra}


def findings(payload: dict) -> list[dict]:
    """One finding per refused path, keyed and shown by its escaped form so no control character reaches a terminal."""
    found = [_finding(path, reasons) for path in sorted(payload.get("writes", {})) if (reasons := judge(path))]
    return found + [_finding(name, reasons, new=True) for name in padded_names(payload) if (reasons := judge(name))]


def main() -> int:
    try:
        found = findings(json.load(sys.stdin))
    except Exception as exc:  # noqa: BLE001 -- a fault must not read as a verdict
        print(
            f"refname-filename-metachar-gate: internal error ({type(exc).__name__}); paths not checked", file=sys.stderr
        )
        return 2
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print("refname-filename-metachar: path name refused:", file=sys.stderr)
    for item in found:
        print(f"  {item['message']}", file=sys.stderr)
    print(ADVICE, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

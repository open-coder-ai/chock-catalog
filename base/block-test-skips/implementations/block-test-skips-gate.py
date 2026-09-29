#!/usr/bin/env python3
"""Refuse a change that adds a test skip or focus marker to a test file."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter

TEST_PATH = re.compile(
    r"(^|/)(tests?/|__tests__/|test_[^/]*\.py$|[^/]*_test\.(py|go)$|[^/]*\.(test|spec)\.[cm]?[jt]sx?$|src/test/)"
)
SKIP = re.compile(
    r"@pytest\.mark\.skip\b|@pytest\.mark\.skipif\b|@unittest\.skip|\b(it|describe|test)\.skip\("
    r"|\bx(it|describe)\(|\b(it|describe|test)\.only\(|@Disabled\b|@Ignore\b|\bt\.Skip(Now|f)?\("
)
WAIVER = re.compile(r"chock:\s*allow\s+test-skip")
COMMENT_PREFIXES = ("#", "//", "*", "/*")
FALSY = {"", "0", "false", "no", "off"}


def head_lines(root: str, path: str) -> Counter[str]:
    """The lines of `path` at HEAD; empty when HEAD or the file does not exist."""
    proc = subprocess.run(  # noqa: S603 -- fixed argv, path comes from the runner's own staged list
        ["git", "show", f"HEAD:{path}"],  # noqa: S607
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return Counter(proc.stdout.splitlines()) if proc.returncode == 0 else Counter()


def added(text: str, before: Counter[str]) -> list[tuple[int, str]]:
    """(line number, line) for every line beyond the copies HEAD already had."""
    seen: Counter[str] = Counter()
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        seen[line] += 1
        if seen[line] > before[line]:
            out.append((number, line))
    return out


def waivable(event: str) -> bool:
    """A waiver counts only at commit, and never for a commit an agent marked as its own."""
    agent = os.environ.get("CHOCK_AGENT_COMMIT", "").strip().lower() not in FALSY
    return event == "commit" and not agent


def findings(payload: dict) -> list[str]:
    waive = waivable(str(payload.get("event", "")))
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        norm = path.replace("\\", "/")
        if not TEST_PATH.search(norm):
            continue
        for number, line in added(text, head_lines(payload["repo_root"], norm)):
            if line.lstrip().startswith(COMMENT_PREFIXES) or not SKIP.search(line):
                continue
            if waive and WAIVER.search(line):
                continue
            found.append(f"{norm}:{number}: {line.strip()[:120]}")
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("block-test-skips: stdin is not the gate JSON", file=sys.stderr)
        return 2
    found = findings(payload)
    if not found:
        return 0
    print("block-test-skips: this change adds a test skip or focus marker:", file=sys.stderr)
    for item in found:
        print(f"  {item}", file=sys.stderr)
    print(
        "Fix the test or the code rather than skipping it. A reviewed skip needs a person to add "
        "'chock: allow test-skip' on the line and commit from their own shell; in the agent, or for "
        "an agent's commit, only a skip already committed in HEAD counts.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

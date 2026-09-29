#!/usr/bin/env python3
"""Refuse an agent-memory write that pastes git history, a long code block, a duplicate or a secret."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter

MEMORY_PATH = re.compile(r"(^|/)MEMORY\.md$|^CLAUDE\.local\.md$|^\.claude/memory/|^memory/.+\.md$")
HISTORY = re.compile(
    r"^diff --git |^@@ -\d+(,\d+)? \+\d+(,\d+)? @@|^commit [0-9a-f]{40}$|^index [0-9a-f]{7,}\.\.[0-9a-f]{7,}"
)
# scan-secrets' content_pattern, verbatim; tests/policies/test_guard_memory_writes.py fails on drift.
SECRET = re.compile(
    r"""(?i)((AKIA|ASIA)[0-9A-Z]{16}|gh[oprsu]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}|xox[bpas]-[0-9A-Za-z-]{10,}|(sk|rk)_live_[0-9A-Za-z]{16,}|sk-proj-[0-9A-Za-z_-]{20,}|sk-ant-[0-9A-Za-z_-]{20,}|sk-[0-9A-Za-z]{20,}|AIza[0-9A-Za-z_-]{35}|npm_[0-9A-Za-z]{36}|SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}|eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*|-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----|api[_-]?key\s*=\s*["'][A-Za-z0-9_\-]{20,}["']|secret[_-]?key\s*=\s*["'][A-Za-z0-9_\-]{20,}["']|auth[_-]?token\s*=\s*["'][A-Za-z0-9_\-]{20,}["']|password\s*=\s*["'][^"'\s]{12,}["']|(api|secret|auth)[_-]?(key|token)\s*[=:]\s*[A-Za-z0-9_\-]{20,}|password\s*[=:]\s*[^\s"'${}]{12,})"""
)
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
BULLET = re.compile(r"^([-*+]|\d+[.)])\s+")
MAX_BLOCK_LINES = 20


def head_lines(root: str, path: str) -> Counter[str]:
    """The lines of `path` at HEAD; empty when HEAD or the file does not exist."""
    proc = subprocess.run(  # noqa: S603 -- fixed argv, path comes from the runner's own list
        ["git", "show", f"HEAD:{path}"],  # noqa: S607
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return Counter(proc.stdout.splitlines()) if proc.returncode == 0 else Counter()


def new_line_numbers(lines: list[str], before: Counter[str]) -> set[int]:
    """1-based numbers of the lines beyond the copies HEAD already had."""
    seen: Counter[str] = Counter()
    fresh = set()
    for number, line in enumerate(lines, 1):
        seen[line] += 1
        if seen[line] > before[line]:
            fresh.add(number)
    return fresh


def fenced_blocks(lines: list[str]) -> tuple[set[int], list[tuple[int, int]]]:
    """(line numbers inside any fence, [(opening line, body length)] for each block)."""
    inside: set[int] = set()
    blocks: list[tuple[int, int]] = []
    opener: tuple[int, str] | None = None
    for number, line in enumerate(lines, 1):
        match = FENCE.match(line)
        if opener is None:
            if match:
                opener = (number, match.group(1))
                inside.add(number)
        elif match and match.group(1)[0] == opener[1][0] and len(match.group(1)) >= len(opener[1]):
            blocks.append((opener[0], number - opener[0] - 1))
            inside.add(number)
            opener = None
        else:
            inside.add(number)
    if opener:
        blocks.append((opener[0], len(lines) - opener[0]))
    return inside, blocks


def normalize(line: str) -> str:
    return BULLET.sub("", " ".join(line.split()))


def duplicates(lines: list[str], skip: set[int]) -> list[tuple[int, int]]:
    """(later line, first line) for each repeated entry; headings, blanks and fenced code ignored."""
    first: dict[str, int] = {}
    repeats = []
    for number, line in enumerate(lines, 1):
        key = normalize(line)
        if number in skip or key.startswith("#") or not any(c.isalnum() for c in key):
            continue
        if key in first:
            repeats.append((number, first[key]))
        else:
            first[key] = number
    return repeats


def judge(path: str, text: str, before: Counter[str]) -> list[str]:
    lines = text.splitlines()
    fresh = new_line_numbers(lines, before)
    inside, blocks = fenced_blocks(lines)
    found: dict[int, str] = {}
    for number in sorted(fresh):
        if HISTORY.search(lines[number - 1]):
            found[number] = "pasted git history"
        elif SECRET.search(lines[number - 1]):
            found[number] = "secret"
    for start, length in blocks:
        if length > MAX_BLOCK_LINES and any(start <= n <= start + length + 1 for n in fresh):
            found.setdefault(start, f"fenced code block of {length} lines (limit {MAX_BLOCK_LINES})")
    for number, original in duplicates(lines, inside):
        if number in fresh or original in fresh:
            found.setdefault(number, f"duplicates line {original}")
    return [f"{path}:{number}: {reason}" for number, reason in sorted(found.items())]


def findings(payload: dict) -> list[str]:
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        norm = path.replace("\\", "/")
        if MEMORY_PATH.search(norm):
            found += judge(norm, text, head_lines(payload["repo_root"], norm))
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("guard-memory-writes: stdin is not the gate JSON", file=sys.stderr)
        return 2
    found = findings(payload)
    if not found:
        return 0
    print("guard-memory-writes: memory must not hold this (path:line):", file=sys.stderr)
    for item in found:
        print(f"  {item}", file=sys.stderr)
    print(
        "Keep memory to short, non-derivable facts: link to a commit or file instead of pasting "
        "it, drop duplicates, never store a secret (rotate any that was written). No waiver exists.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

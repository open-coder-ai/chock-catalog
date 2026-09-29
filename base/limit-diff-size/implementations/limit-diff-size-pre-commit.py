#!/usr/bin/env python3
"""Ask about a commit whose staged hand-written diff exceeds a line limit (exit 3)."""

from __future__ import annotations

import fnmatch
import os
import subprocess
import sys

DEFAULT_LIMIT = 500
ASK = 3  # the hook refuses an ask until a person sets CHOCK_ALLOW=limit-diff-size
TOP_FILES = 5
FALSY = {"", "0", "false", "no", "off"}
LOCKFILES = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
    "*.lock",
    "*.min.js",
    "*.min.css",
    "*.snap",
)
#: Directory names skipped at any depth; `.chock/` only at the repository root.
GENERATED_DIRS = frozenset({"vendor", "node_modules", "dist", "build"})


def truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() not in FALSY


def limit() -> int:
    """CHOCK_DIFF_LIMIT when it is a positive integer, else the default."""
    raw = os.environ.get("CHOCK_DIFF_LIMIT", "").strip()
    return int(raw) if raw.isdecimal() and int(raw) > 0 else DEFAULT_LIMIT


def excluded(path: str) -> bool:
    parts = path.split("/")
    if parts[0] == ".chock" or GENERATED_DIRS & set(parts[:-1]):
        return True
    return any(fnmatch.fnmatchcase(parts[-1], pattern) for pattern in LOCKFILES)


def parse_numstat(raw: str) -> list[tuple[str, int]]:
    """(path, added + removed) for each counted text file of a `--numstat -z` listing."""
    tokens = raw.split("\0")
    rows: list[tuple[str, int]] = []
    i = 0
    while i < len(tokens) and tokens[i]:
        added, removed, path = tokens[i].split("\t", 2)
        i += 1
        if not path:  # a rename: the next two tokens are the old and the new path
            path = tokens[i + 1]
            i += 2
        if added != "-" and not excluded(path):
            rows.append((path, int(added) + int(removed)))
    return rows


def staged_rows() -> list[tuple[str, int]] | None:
    proc = subprocess.run(
        ["git", "diff", "--cached", "--numstat", "-z", "-M"],  # noqa: S607
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return parse_numstat(proc.stdout) if proc.returncode == 0 else None


def main() -> int:
    rows = staged_rows()
    if rows is None:
        print(
            "limit-diff-size: `git diff --cached` failed; refusing rather than allowing an unmeasured diff",
            file=sys.stderr,
        )
        return 1
    total, cap = sum(n for _, n in rows), limit()
    if total <= cap:
        return 0
    if truthy("CHOCK_ALLOW_LARGE_DIFF"):
        if truthy("CHOCK_AGENT_COMMIT"):
            print(
                "limit-diff-size: CHOCK_ALLOW_LARGE_DIFF ignored, this is an agent's commit (CHOCK_AGENT_COMMIT is set)",
                file=sys.stderr,
            )
        else:
            print(
                f"limit-diff-size: {total} lines over the {cap} limit, allowed by CHOCK_ALLOW_LARGE_DIFF",
                file=sys.stderr,
            )
            return 0
    print(f"limit-diff-size: staged diff is {total} lines (added + removed), limit is {cap}.", file=sys.stderr)
    print("Largest files (lockfiles, vendored, generated and binary files not counted):", file=sys.stderr)
    for path, n in sorted(rows, key=lambda row: (-row[1], row[0]))[:TOP_FILES]:
        print(f"  {n:6d}  {path}", file=sys.stderr)
    print(
        "Split it: `git reset` then stage one concern at a time with `git add -p`, one commit each. "
        "To commit it whole, a person runs that one commit with CHOCK_ALLOW=limit-diff-size "
        "(CHOCK_ALLOW_LARGE_DIFF=1 still works) or raises CHOCK_DIFF_LIMIT; "
        "an agent must ask the person and never sets any of them itself.",
        file=sys.stderr,
    )
    return ASK


if __name__ == "__main__":
    sys.exit(main())

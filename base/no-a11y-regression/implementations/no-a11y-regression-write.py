#!/usr/bin/env python3
"""Judge an agent's markup write against the revision it replaces, with the commit guard's own table."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _guard():
    """The commit-time guard, loaded from beside this file so the two can never disagree."""
    path = _HERE / "no-a11y-regression-pre-commit.py"
    spec = importlib.util.spec_from_file_location("no_a11y_regression_pre_commit", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # its dataclasses look their own module up by name
    spec.loader.exec_module(module)
    return module


def _head(root: Path, path: str) -> str:
    """The committed text of `path`; a path git cannot show has no content."""
    proc = subprocess.run(  # noqa: S603 -- fixed argv, no shell; `path` is a key of the runner's own writes
        ["git", "-c", "core.quotePath=false", "show", f"HEAD:{path}"],  # noqa: S607
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def baseline(root: Path, path: str, after: str) -> str:
    """What the write replaces: the file on disk, or HEAD when disk already holds `after` (the turn's end)."""
    target = root / path
    disk = target.read_text(encoding="utf-8", errors="replace") if target.is_file() else None
    return disk if disk is not None and disk != after else _head(root, path)


def judge(payload: dict) -> list[str]:
    """One refusal block per written markup file that retracts a name its previous revision carried."""
    guard = _guard()
    root = Path(payload["repo_root"])
    lines: list[str] = []
    for path, after in sorted((payload.get("writes") or {}).items()):
        if not path.endswith(guard.MARKUP_SUFFIXES):
            continue
        try:
            rows = guard.evaluate(baseline(root, path, after), after)
        except Exception as exc:  # noqa: BLE001 -- a parse failure is not evidence of a violation
            print(f"no-a11y-regression: skipped {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        for row in (r for r in rows if r["action"] == guard.DENY):
            lines += [
                f"  {path}: {row['ref']}   {row['key'][0]} -> {row['key'][1]}",
                f"      {row['why']}",
                f"      was: {row['was']}",
                f"      now: {row['now']}",
            ]
    return lines


def main() -> int:
    """Exit 1 with the reasons when a write destroys an accessibility assertion, else 0."""
    lines = judge(json.load(sys.stdin))
    if not lines:
        return 0
    print(
        "no-a11y-regression: this write destroys an accessibility assertion its previous revision carried. "
        "A removed element and an emptied alt both score as fewer violations, so no report will show it.",
        file=sys.stderr,
    )
    print("\n".join(lines), file=sys.stderr)
    print(
        "Restore what the element carried, or -- if it truly is decorative -- say so where a reviewer sees it.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

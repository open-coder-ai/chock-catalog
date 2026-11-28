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


class Review:
    """What a write set came to: the refusal blocks, the waivers it adds, and the findings a waiver let through."""

    def __init__(self, added: list) -> None:
        self.lines: list[str] = []
        self.added = added
        self.logged = 0


def review(payload: dict) -> Review:
    """Judge each written markup file against its previous revision, and the sidecar against HEAD's."""
    guard = _guard()
    root = Path(payload["repo_root"])
    writes = payload.get("writes") or {}
    written = next((text for path, text in writes.items() if guard.waiver.is_sidecar(path)), None)
    honoured = guard.waiver.read(guard.waiver.show(f"HEAD:./{guard.waiver.PATH}", root), written, person=False)
    done = Review(honoured.added)
    for problem in honoured.problems:
        print(f"no-a11y-regression: {problem}", file=sys.stderr)
    for path, after in sorted(writes.items()):
        if not path.endswith(guard.MARKUP_SUFFIXES):
            continue
        try:
            rows = guard.evaluate(baseline(root, path, after), after)
        except Exception as exc:  # noqa: BLE001 -- a parse failure is not evidence of a violation
            print(f"no-a11y-regression: skipped {path}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        guard.waive(path, rows, honoured)
        for row in (r for r in rows if r["action"] == guard.WARN):
            print(f"no-a11y-regression: warning: {path}: {row['ref']}   {row['why']}", file=sys.stderr)
        for row in (r for r in rows if r["action"] == guard.WAIVED):
            print(guard.waived_line(path, row), file=sys.stderr)
            done.logged += 1
        for row in (r for r in rows if r["action"] == guard.DENY):
            done.lines += [
                f"  {path}: {row['ref']}   {row['key'][0]} -> {row['key'][1]}",
                f"      {row['why']}",
                f"      was: {row['was']}",
                f"      now: {row['now']}",
            ]
    return done


def judge(payload: dict) -> list[str]:
    """One refusal block per written markup file that retracts a name its previous revision carried."""
    return review(payload).lines


def main() -> int:
    """Exit 1 when a write destroys an accessibility assertion or adds a waiver; 4 when a waiver let one through."""
    guard = _guard()
    done = review(json.load(sys.stdin))
    if not (done.lines or done.added):
        return guard.waiver.EXIT_WARN if done.logged else 0
    if done.lines:
        print(
            "no-a11y-regression: this write destroys an accessibility assertion its previous revision carried. "
            "A removed element and an emptied alt both score as fewer violations, so no report will show it.",
            file=sys.stderr,
        )
        print("\n".join(done.lines), file=sys.stderr)
    if done.added:
        print(
            f"no-a11y-regression: this write adds a waiver, and a waiver is a person's decision, so none of it counts "
            f"({len(done.added)} entr{'y' if len(done.added) == 1 else 'ies'}):",
            file=sys.stderr,
        )
        print("\n".join(guard.added_line(entry) for entry in done.added), file=sys.stderr)
    print(f"Restore what the element carried. {guard.waiver_hint()}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

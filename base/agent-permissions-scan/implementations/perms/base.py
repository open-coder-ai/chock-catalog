"""The revision a change is judged against: HEAD at a commit, the range base in CI (None when CI cannot name one)."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
SHA = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")
EVENT_LIMIT = 1_000_000


def _resolve(root: Path, rev: str) -> str | None:
    """The commit `rev` names as a full id, or None when it names none."""
    try:
        proc = subprocess.run(  # noqa: S603 -- a fixed git argv; `rev` is validated and follows `--end-of-options`
            ["git", "rev-parse", "--verify", "--quiet", "--end-of-options", f"{rev}^{{commit}}"],  # noqa: S607
            cwd=root,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    out = proc.stdout.decode("ascii", "replace").strip()
    return out if proc.returncode == 0 and SHA.fullmatch(out) else None


def _pushed_before() -> str:
    try:
        with Path(os.environ.get("GITHUB_EVENT_PATH", "")).open(encoding="utf-8") as handle:
            before = json.loads(handle.read(EVENT_LIMIT)).get("before")
    except (OSError, ValueError, AttributeError):
        return ""
    return before if isinstance(before, str) and SHA.fullmatch(before) and set(before) != {"0"} else ""


def ci_base(root: Path, payload: dict) -> str | None:
    """The commit id the CI change started from: the payload's `base`, the pull request base, or the push's `before`."""
    named = payload.get("base")
    if isinstance(named, str) and named:
        return _resolve(root, named) if REF.fullmatch(named) and not named.startswith("-") else None
    ref = os.environ.get("GITHUB_BASE_REF", "").strip()
    if ref:
        return _resolve(root, f"origin/{ref}") if REF.fullmatch(ref) else None
    before = _pushed_before()
    return _resolve(root, before) if before else None

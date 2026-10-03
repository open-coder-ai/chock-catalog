"""Where a change comes from: the staged diff at commit, the PR diff in CI, or an agent's write against its baseline."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from diffshape.hunks import Hunk, from_texts, parse_patch

GIT_TIMEOUT = 25
DIFF = [
    "diff", "-U0", "--text", "--no-color", "--no-ext-diff", "--no-textconv", "-M", "--relative",
    "--src-prefix=a/", "--dst-prefix=b/",
]  # fmt: skip
#: Branch names reach git as `origin/<name>`; anything else in the variable is not a base.
EVENT_LIMIT = 1 << 20
SHA = re.compile(r"[0-9a-f]{40}")
BASE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")


class ChangeError(RuntimeError):
    """The change cannot be read, so it cannot be judged."""


def git(root: Path, *args: str) -> str:
    """Text output of a git command run in `root`; ChangeError when git fails or is not there."""
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            ["git", "-c", "core.quotePath=false", *args],  # noqa: S607
            cwd=root,
            capture_output=True,
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        msg = f"git {args[0]} could not run ({type(exc).__name__})"
        raise ChangeError(msg) from None
    if proc.returncode != 0:
        msg = f"git {args[0]} failed: {proc.stderr.decode('utf-8', 'replace').strip()[:200]}"
        raise ChangeError(msg)
    return proc.stdout.decode("utf-8", errors="replace")


def _resolves(root: Path, ref: str) -> bool:
    try:
        git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except ChangeError:
        return False
    return True


def staged(root: Path) -> list[Hunk]:
    """Hunks of the staged change, deletions and renames included."""
    return parse_patch(git(root, *DIFF, "--cached"))


def _pushed_before() -> str:
    """The commit a push event started from, read from the CI's event file; empty when there is none."""
    try:
        with Path(os.environ.get("GITHUB_EVENT_PATH", "")).open(encoding="utf-8") as handle:
            before = json.loads(handle.read(EVENT_LIMIT)).get("before")
    except (OSError, ValueError, AttributeError):
        return ""
    return before if isinstance(before, str) and SHA.fullmatch(before) and set(before) != {"0"} else ""


def ci_range(root: Path) -> list[str] | None:
    """The git range of the change under test: the pull request's base when the CI names one, else the tip commit.

    None for a root commit, which removes nothing. A named base that does not resolve raises ChangeError.
    """
    name = os.environ.get("GITHUB_BASE_REF", "").strip()
    if name:
        ref = f"origin/{name}"
        if not BASE_REF.fullmatch(name) or not _resolves(root, ref):
            msg = f"base ref {ref!r} does not resolve; fetch it (actions/checkout fetch-depth: 0)"
            raise ChangeError(msg)
        return [f"{ref}...HEAD"]
    before = _pushed_before()
    if before and _resolves(root, before):
        head = git(root, "rev-parse", "HEAD").strip()
        if git(root, "rev-parse", before).strip() != head:
            return [f"{before}...HEAD"]
    if _resolves(root, "HEAD^1"):
        return ["HEAD^1", "HEAD"]
    if git(root, "rev-parse", "--is-shallow-repository").strip() == "true":
        msg = "a shallow checkout has no parent to compare with; fetch more history (actions/checkout fetch-depth: 0)"
        raise ChangeError(msg)
    return None


def in_range(root: Path) -> list[Hunk]:
    """Hunks of the change CI is testing (see ci_range)."""
    span = ci_range(root)
    return parse_patch(git(root, *DIFF, *span)) if span else []


def committed(root: Path, path: str) -> str:
    """The text of `path` at HEAD, or "" when HEAD does not have it."""
    git(root, "rev-parse", "--git-dir")  # a repository git cannot read is an error, not an empty HEAD
    try:
        return git(root, "show", f"HEAD:./{path}")
    except ChangeError:
        return ""


def baseline(root: Path, path: str, after: str) -> str:
    """What a write replaces: the file on disk, or HEAD when disk already holds `after` (the turn's end)."""
    target = root / path
    try:
        disk = target.read_text(encoding="utf-8", errors="replace") if target.is_file() else None
    except OSError:
        disk = None
    return disk if disk is not None and disk != after else committed(root, path)


def repo_path(root: Path, path: str) -> str:
    """`path` relative to the repository root, forward-slashed; ChangeError when it points outside the repository."""
    top = Path(os.path.abspath(root))
    rel = os.path.relpath(os.path.abspath(top / path), top)
    if rel == ".." or rel.startswith(".." + os.sep) or os.path.isabs(rel):
        msg = f"write path {path!r} is outside the repository"
        raise ChangeError(msg)
    return rel.replace(os.sep, "/")


def written(root: Path, writes: dict[str, str]) -> list[Hunk]:
    """Hunks of an agent's writes against their baselines, by repository-relative path."""
    hunks: list[Hunk] = []
    for path, after in sorted(writes.items()):
        rel = repo_path(root, path)
        hunks += from_texts(rel, baseline(root, rel, after), after)
    return hunks

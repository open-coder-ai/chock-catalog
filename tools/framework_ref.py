#!/usr/bin/env python3
"""The framework pin is one full commit SHA, a checkout of it is that commit, clean, and its pinned deps are installed."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_FILE = ".framework-ref"
SHA = re.compile(r"[0-9a-f]{40}")
REFUSED = 2
# PEP 508 direct reference: `name[extras] @ url ; marker`. Version specifiers are pip check's job.
DIRECT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@\s*([^\s;]+)")
GIT_COMMIT = re.compile(r"git\+(https://github\.com/[^@\s]+?)(?:\.git)?@([0-9a-f]{40})")


def valid(ref: str) -> bool:
    """True only for 40 lowercase hex: a branch, tag, short or uppercase SHA is a name, not a commit."""
    return SHA.fullmatch(ref) is not None


def read_pin(root: Path = ROOT) -> str | None:
    """The pinned SHA: the file holds exactly 40 lowercase hex and at most one trailing newline."""
    try:
        text = (root / PIN_FILE).read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    ref = text.removesuffix("\n")
    return ref if valid(ref) else None


def _git(path: str, *args: str) -> subprocess.CompletedProcess[str]:
    # No inherited GIT_DIR/GIT_WORK_TREE redirect, and no replace object stands in for the pinned commit.
    # No global/system config either: an fsmonitor hook there could blind the clean-worktree check.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")} | {
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    cmd = ["git", "-c", "core.fsmonitor=false", "-C", path, *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)


def _head(path: str) -> str:
    """The checked-out commit, or "" when there is none or the worktree differs from it."""
    head = _git(path, "rev-parse", "--verify", "HEAD^{commit}")
    status = _git(path, "status", "--porcelain", "--untracked-files=all", "--ignored")
    if head.returncode or status.returncode or status.stdout:
        return ""
    return head.stdout.strip()


def _refuse(message: str) -> int:
    print(f"::error::{message}", file=sys.stderr)
    return REFUSED


def _read() -> int:
    ref = read_pin(ROOT)
    if ref is None:
        return _refuse(f"{PIN_FILE} must hold one full 40-character lowercase commit SHA and nothing else")
    env_file = os.environ.get("GITHUB_ENV")
    if env_file:
        with Path(env_file).open("a", encoding="utf-8") as handle:
            handle.write(f"FRAMEWORK_REF={ref}\n")
    print(f"FRAMEWORK_REF={ref}")
    return 0


def _env_ref() -> str | None:
    ref = os.environ.get("FRAMEWORK_REF", "")
    return ref if valid(ref) else None


def _check() -> int:
    if _env_ref() is None:
        return _refuse("FRAMEWORK_REF must be a full 40-character lowercase commit SHA (no branch, tag or short SHA)")
    print("FRAMEWORK_REF is a full commit SHA")
    return 0


def _verify(path: str) -> int:
    ref = _env_ref()
    if ref is None:
        return _refuse("FRAMEWORK_REF must be a full 40-character lowercase commit SHA (no branch, tag or short SHA)")
    head = _head(path)
    if head != ref:
        return _refuse(
            f"{path} is checked out at {head or 'no clean commit'}, not the pinned {ref}; refusing to use it"
        )
    print(f"{path} is the pinned commit {ref}")
    return 0


def _installed(name: str) -> tuple[dict, str] | None:
    """(PEP 610 direct_url.json, version) of an installed distribution; {} for an index install."""
    try:
        dist = distribution(name)
    except PackageNotFoundError:
        return None
    try:
        origin = json.loads(dist.read_text("direct_url.json") or "{}")
    except ValueError:
        origin = {}
    return (origin if isinstance(origin, dict) else {}), dist.version


def _accepts(url: str, origin: dict) -> bool:
    """A git commit pin is met by that commit, cloned or as GitHub's archive of it; any other URL by itself."""
    if git := GIT_COMMIT.fullmatch(url):
        repo, commit = git.groups()
        if (origin.get("vcs_info") or {}).get("commit_id") == commit:
            return origin.get("url", "").removeprefix("git+").removesuffix(".git") == repo
        return "archive_info" in origin and origin.get("url") == f"{repo}/archive/{commit}.tar.gz"
    return origin.get("url") == url


def _deps(path: str) -> int:
    try:
        project = tomllib.loads((Path(path) / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    except (OSError, ValueError, KeyError) as err:
        return _refuse(f"{path}/pyproject.toml: no [project] table to read pins from ({err})")
    problems = []
    for requirement in project.get("dependencies", []):
        if not (pin := DIRECT.match(requirement)):
            continue
        name, url = pin.groups()
        if (installed := _installed(name)) is None:
            problems.append(f"{name} is not installed; {path}/pyproject.toml pins {url}")
        elif not _accepts(url, origin := installed[0]):
            have = origin.get("url") or f"{installed[1]} from a package index"
            problems.append(
                f"{path}/pyproject.toml pins {name} @ {url}, but the installed {name} is {have}; "
                "pin the same commit in requirements/framework.in and regenerate requirements/framework.txt"
            )
    if problems:
        return _refuse("; ".join(problems))
    print(f"every direct-reference dependency {path}/pyproject.toml pins is the one installed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("read", help=f"validate {PIN_FILE}; export FRAMEWORK_REF to $GITHUB_ENV")
    sub.add_parser("check", help="validate $FRAMEWORK_REF before anything checks it out")
    verify = sub.add_parser("verify", help="fail unless the checkout at PATH is exactly $FRAMEWORK_REF")
    verify.add_argument("path")
    deps = sub.add_parser("deps", help="fail unless every direct-reference dependency PATH pins is what is installed")
    deps.add_argument("path")
    args = parser.parse_args(argv)
    if args.cmd == "read":
        return _read()
    if args.cmd == "check":
        return _check()
    if args.cmd == "deps":
        return _deps(args.path)
    return _verify(args.path)


if __name__ == "__main__":
    raise SystemExit(main())

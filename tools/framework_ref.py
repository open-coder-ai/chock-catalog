#!/usr/bin/env python3
"""The framework pin is one full commit SHA, a checkout of it is that commit, clean, and so is each git dep it pins."""

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
# PEP 508 direct reference: `name[extras] @ url ; marker`. Version specifiers are requirements/framework.txt's.
DIRECT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@\s*([^\s;]+)")
GIT_COMMIT = re.compile(r"git\+(https://github\.com/open-coder-ai/[A-Za-z0-9._-]+?)(?:\.git)?@([0-9a-f]{40})")


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


def _head(path: str) -> tuple[str, list[str], int]:
    """(checked-out commit, up to 8 status lines, files differing only in line endings).

    The commit is "" when there is none or the worktree differs in more than line endings: a Windows checkout of a
    commit that stores CRLF under an `eol=lf` attribute reports those files modified, and that is not an edit.
    """
    head = _git(path, "rev-parse", "--verify", "HEAD^{commit}")
    edited = any(
        _git(path, "diff", *flags, "--ignore-cr-at-eol", "--quiet").returncode for flags in ((), ("--cached",))
    )
    # Ignored files count as untracked here: a stray ignored setup.py is as much a substitution as a visible one.
    untracked = _git(path, "ls-files", "--others")
    if head.returncode or edited or untracked.returncode or untracked.stdout:
        status = _git(path, "status", "--porcelain", "--untracked-files=all", "--ignored")
        return "", status.stdout.splitlines()[:8], 0
    return head.stdout.strip(), [], _eol_only(path)


def _eol_only(path: str) -> int:
    """How many tracked files git reports modified although only their line endings differ from HEAD."""
    changed = _git(path, "diff", "--name-only", "-z", "HEAD", "--").stdout.split("\0")
    return sum(
        1
        for name in changed
        if name and not _git(path, "diff", "--ignore-cr-at-eol", "--quiet", "HEAD", "--", name).returncode
    )


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
    head, dirty, eol_only = _head(path)
    if head != ref:
        code = _refuse(
            f"{path} is checked out at {head or 'no clean commit'}, not the pinned {ref}; refusing to use it"
        )
        for line in dirty:
            print(f"::notice::{line.encode('unicode_escape').decode('ascii')}", file=sys.stderr)
        return code
    print(f"{path} is the pinned commit {ref}")
    if eol_only:
        print(f"::notice::{eol_only} tracked file(s) in {path} differ from the commit only in line endings")
    return 0


def _pyproject_deps(path: str) -> list[str] | None:
    try:
        return tomllib.loads((Path(path) / "pyproject.toml").read_text(encoding="utf-8"))["project"].get(
            "dependencies", []
        )
    except (OSError, ValueError, KeyError):
        return None


def _direct_deps(path: str) -> int:
    """Print `name@url` per direct reference PATH's pyproject pins; each must be an open-coder-ai commit."""
    if (requirements := _pyproject_deps(path)) is None:
        return _refuse(f"{path}/pyproject.toml: no [project] table to read pins from")
    pins, problems = [], []
    for requirement in requirements:
        if pin := DIRECT.match(requirement):
            name, url = pin.groups()
            if GIT_COMMIT.fullmatch(url):
                pins.append(f"{name}@{url}")
            else:
                problems.append(f"{name} @ {url}")
    if problems:
        return _refuse(
            f"{path}/pyproject.toml pins {', '.join(problems)}; only "
            "git+https://github.com/open-coder-ai/<repo>@<40 lowercase hex> installs without a hash"
        )
    print("\n".join(pins), end="\n" if pins else "")
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


def _deps(path: str) -> int:
    """Fail unless each git commit PATH's pyproject pins is the one installed (pip check compares versions only)."""
    if (requirements := _pyproject_deps(path)) is None:
        return _refuse(f"{path}/pyproject.toml: no [project] table to read pins from")
    problems = []
    for requirement in requirements:
        if not (pin := DIRECT.match(requirement)):
            continue
        name, url = pin.groups()
        git = GIT_COMMIT.fullmatch(url)
        if (installed := _installed(name)) is None:
            problems.append(f"{name} is not installed; {path}/pyproject.toml pins {url}")
            continue
        origin, version = installed
        found = (origin.get("vcs_info") or {}).get("commit_id")
        repo = origin.get("url", "").removeprefix("git+").removesuffix(".git")
        if not git or (repo, found) != git.groups():
            have = f"{repo}@{found}" if found else origin.get("url") or f"{version} from a package index"
            problems.append(f"{path}/pyproject.toml pins {name} @ {url}, but the installed {name} is {have}")
    if problems:
        return _refuse("; ".join(problems))
    print(f"every git dependency {path}/pyproject.toml pins is installed at its commit")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("read", help=f"validate {PIN_FILE}; export FRAMEWORK_REF to $GITHUB_ENV")
    sub.add_parser("check", help="validate $FRAMEWORK_REF before anything checks it out")
    verify = sub.add_parser("verify", help="fail unless the checkout at PATH is exactly $FRAMEWORK_REF")
    verify.add_argument("path")
    direct = sub.add_parser("direct-deps", help="print the git commit pins in PATH's pyproject, one per line")
    direct.add_argument("path")
    deps = sub.add_parser("deps", help="fail unless each git commit PATH's pyproject pins is the one installed")
    deps.add_argument("path")
    args = parser.parse_args(argv)
    if args.cmd == "read":
        return _read()
    if args.cmd == "check":
        return _check()
    if args.cmd == "direct-deps":
        return _direct_deps(args.path)
    if args.cmd == "deps":
        return _deps(args.path)
    return _verify(args.path)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""The framework pin is one full commit SHA, a checkout of it is that commit, clean, and its git pins are commits too."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_FILE = ".framework-ref"
SHA = re.compile(r"[0-9a-f]{40}")
REFUSED = 2
# PEP 508 direct reference: `name[extras] @ url ; marker`. Version specifiers are requirements/framework.txt's.
DIRECT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@\s*([^\s;]+)")
GIT_COMMIT = re.compile(r"git\+https://github\.com/open-coder-ai/[A-Za-z0-9._-]+@[0-9a-f]{40}")


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


def _direct_deps(path: str) -> int:
    """Print `name@url` per direct reference PATH's pyproject pins; each must be an open-coder-ai commit."""
    try:
        project = tomllib.loads((Path(path) / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    except (OSError, ValueError, KeyError) as err:
        return _refuse(f"{path}/pyproject.toml: no [project] table to read pins from ({err})")
    pins, problems = [], []
    for requirement in project.get("dependencies", []):
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("read", help=f"validate {PIN_FILE}; export FRAMEWORK_REF to $GITHUB_ENV")
    sub.add_parser("check", help="validate $FRAMEWORK_REF before anything checks it out")
    verify = sub.add_parser("verify", help="fail unless the checkout at PATH is exactly $FRAMEWORK_REF")
    verify.add_argument("path")
    direct = sub.add_parser("direct-deps", help="print the git commit pins in PATH's pyproject, one per line")
    direct.add_argument("path")
    args = parser.parse_args(argv)
    if args.cmd == "read":
        return _read()
    if args.cmd == "check":
        return _check()
    if args.cmd == "direct-deps":
        return _direct_deps(args.path)
    return _verify(args.path)


if __name__ == "__main__":
    raise SystemExit(main())

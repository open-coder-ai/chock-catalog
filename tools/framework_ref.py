#!/usr/bin/env python3
"""The framework pin is one full commit SHA, and a checkout of it is that commit or the job fails."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN_FILE = ".framework-ref"
SHA = re.compile(r"[0-9a-f]{40}")
REFUSED = 2


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


def _head(path: str) -> str:
    out = subprocess.run(
        ["git", "-C", path, "rev-parse", "--verify", "HEAD^{commit}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() if out.returncode == 0 else ""


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
        return _refuse(f"{path} is checked out at {head or 'no commit'}, not the pinned {ref}; refusing to use it")
    print(f"{path} is the pinned commit {ref}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("read", help=f"validate {PIN_FILE}; export FRAMEWORK_REF to $GITHUB_ENV")
    sub.add_parser("check", help="validate $FRAMEWORK_REF before anything checks it out")
    verify = sub.add_parser("verify", help="fail unless the checkout at PATH is exactly $FRAMEWORK_REF")
    verify.add_argument("path")
    args = parser.parse_args(argv)
    if args.cmd == "read":
        return _read()
    if args.cmd == "check":
        return _check()
    return _verify(args.path)


if __name__ == "__main__":
    raise SystemExit(main())

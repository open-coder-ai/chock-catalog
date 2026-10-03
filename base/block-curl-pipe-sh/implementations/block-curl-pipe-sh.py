#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse a network download wired into a shell or interpreter (pipe, substitution, here-string, download-then-run).
# Best effort, not a security boundary: aliases, functions, outside variables and encoded commands are out of reach.

import os
import sys

from chock_shellparse import is_powershell
from curlpipe_judge import Judge
from curlpipe_verdict import FETCH_HINT, Verdict, crude, refuse, strongest


def check(raw: str) -> Verdict:
    """The verdict for a command line; under CHOCK_ARGV_FALLBACK the crude reading is applied too."""
    fallback = crude(raw) if os.environ.get("CHOCK_ARGV_FALLBACK") == "1" else None
    text = raw.replace("`", "").replace("\\", "/") if is_powershell(raw) else raw
    try:
        found = Judge().line(text)
    except RecursionError:
        found = refuse("a command nested too deep to read names a downloader") if FETCH_HINT.search(raw) else None
    return strongest([fallback, found])


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        verdict = check(os.environ.get("CHOCK_RAW_COMMAND") or " ".join(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(f"block-curl-pipe-sh: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if verdict:
        print(verdict[1], file=sys.stderr)
    return verdict[0] if verdict else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Refuse destructive commands (rm -rf on a root/home path, force pushes, drops, prunes); ask before ambiguous ones.
# Best effort, not a security boundary: aliases, interpreters and indirect scripts are out of reach.
# The verdicts live in chock_destructive's table, which rtk-dangerous-actions-blocker reads too.

import sys

import chock_destructive


def check(raw: str) -> chock_destructive.Verdict:
    """The verdict for a command line: a block wins over an ask, which wins over silence."""
    return chock_destructive.check(raw)


def run(argv: list[str]) -> int:
    """Exit 1 blocks, 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    try:
        verdict = check(chock_destructive.raw_command(argv))
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a block
        print(
            f"block-destructive-commands: internal error ({type(exc).__name__}); command not checked", file=sys.stderr
        )
        return 2
    if verdict:
        print(verdict[1], file=sys.stderr)
    return verdict[0] if verdict else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

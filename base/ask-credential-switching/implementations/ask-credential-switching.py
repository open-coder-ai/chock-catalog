#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Ask before a shell command switches the cloud or cluster identity later commands act as; never refuse.
# Exit 3 asks (the first line printed is the prompt), exit 0 stays silent, exit 2 reports a guard fault.
# Friction, not a boundary: scripts, SDK code, env files and credential_process are out of reach.

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

FAULT: ImportError | None = None
try:
    import credential_allowlist as allowlist
    import credential_shapes as shapes
    from chock_shellparse import commands
except ImportError as exc:  # a missing shared module is a fault, never a verdict; run() reports it
    FAULT = exc

ASK = 3
SHOWN = 3


def found(raw: str) -> list[shapes.Switch]:
    """Each switch the line makes, in order; a trailing no-op command carries what the line exports."""
    out: list[shapes.Switch] = []
    for cmd in commands(f"{raw}\n:"):
        out += [hit for hit in shapes.switches(cmd) if hit not in out]
    return out


def check(raw: str, root: Path) -> str | None:
    """The ask prompt for a command line, or None when it switches to nothing or only to listed identities."""
    hits = found(raw)
    if not hits:
        return None
    listed, broken = allowlist.load(root)
    left = [hit for hit in hits if hit.identity is None or hit.identity not in listed.get(hit.provider, ())]
    if not left:
        return None
    named = "; ".join(hit.what for hit in left[:SHOWN]) + (
        f"; and {len(left) - SHOWN} more" if len(left) > SHOWN else ""
    )
    note = f" ({broken})" if broken else ""
    return (
        f"CONFIRM: this command switches the identity later commands act as: {named}. Ask the person whether that identity is the one "
        f"intended before it runs. A person lists identities they approve in {allowlist.PATH}, in their own commit{note}."
    )


def run(argv: list[str]) -> int:
    """Exit 3 asks, 2 reports a guard fault (never a verdict), 0 allows."""
    if FAULT is not None:
        print(
            f"ask-credential-switching: internal error ({type(FAULT).__name__}); command not checked", file=sys.stderr
        )
        return 2
    try:
        prompt = check(os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv), Path.cwd())
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a verdict
        print(f"ask-credential-switching: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if prompt:
        print(prompt, file=sys.stderr)
    return ASK if prompt else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

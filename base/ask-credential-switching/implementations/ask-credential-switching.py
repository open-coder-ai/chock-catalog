#!/bin/sh
# fmt: off
"exec" "$(command -v python3 || command -v python)" "$0" "$@"
# fmt: on
# Ask before a shell command switches the cloud or cluster identity later commands act as; never refuse.
# Exit 3 asks (the first line printed is the prompt), exit 0 stays silent, exit 2 reports a guard fault.
# CHOCK_CAN_ASK=0 (the client cannot prompt here) lets a switch through with a stderr note; unset means it can ask.
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
CANNOT_ASK = "0"


def found(raw: str) -> list[shapes.Switch]:
    """Each identity the line switches to, once, in order; a trailing no-op command carries what the line exports."""
    out: list[shapes.Switch] = []
    for cmd in commands(f"{raw}\n:"):
        out += [hit for hit in shapes.switches(cmd, raw) if hit[:2] not in {seen[:2] for seen in out}]
    return out


def unlisted(raw: str, root: Path) -> tuple[str, str]:
    """What the line switches to outside the allowlist, named ("" for nothing), and why the list was not honoured."""
    hits = found(raw)
    if not hits:
        return "", ""
    listed, broken = allowlist.load(root)
    left = [hit for hit in hits if hit.identity is None or hit.identity not in listed.get(hit.provider, ())]
    named = "; ".join(hit.what for hit in left[:SHOWN]) + (
        f"; and {len(left) - SHOWN} more" if len(left) > SHOWN else ""
    )
    return (named if left else ""), broken


def check(raw: str, root: Path) -> str | None:
    """The ask prompt for a command line, or None when it switches to nothing or only to listed identities."""
    named, broken = unlisted(raw, root)
    if not named:
        return None
    note = f" ({broken})" if broken else ""
    return (
        f"CONFIRM: this command switches the identity later commands act as: {named}. Ask the person whether that identity is the one "
        f"intended before it runs. A person lists identities they approve in {allowlist.PATH}, in their own commit{note}."
    )


def run(argv: list[str]) -> int:
    """Exit 3 asks, 2 reports a guard fault (never a verdict), 0 allows; where the client cannot prompt, 0 with a note."""
    if FAULT is not None:
        print(
            f"ask-credential-switching: internal error ({type(FAULT).__name__}); command not checked", file=sys.stderr
        )
        return 2
    raw = os.environ.get("CHOCK_RAW_COMMAND") or shlex.join(argv)
    try:
        if os.environ.get("CHOCK_CAN_ASK") == CANNOT_ASK:
            named, _ = unlisted(raw, Path.cwd())
            if named:
                print(f"ask-credential-switching: let through, this client cannot prompt here: {named}", file=sys.stderr)
            return 0
        prompt = check(raw, Path.cwd())
    except Exception as exc:  # noqa: BLE001 -- a guard fault must not look like a verdict
        print(f"ask-credential-switching: internal error ({type(exc).__name__}); command not checked", file=sys.stderr)
        return 2
    if prompt:
        print(prompt, file=sys.stderr)
    return ASK if prompt else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

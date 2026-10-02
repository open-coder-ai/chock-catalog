#!/usr/bin/env python3
# Refuse a push that creates or moves a branch or tag whose name a shell, a CI step or git can misread, or that has
# the shape of a full commit id. git feeds pre-push one line per ref, "<local ref> <local sha> <remote ref> <remote
# sha>", on stdin; the remote ref is the name being published. A deletion (local sha all zeros) is cleanup and passes.
# A line git would never write is refused: this hook does not guess at what it cannot read.

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from refname_rules import describe, ref_problems, shown

FIELDS = 4  # git's fixed pre-push line: local ref, local sha, remote ref, remote sha


def refused(lines: list[str]) -> list[str]:
    """One reason per pushed ref that is refused, or per line that is not git's pre-push form."""
    reasons = []
    for line in lines:
        parts = line.split(" ")  # git separates with one space; a ref may hold other whitespace
        if not line.strip():
            continue
        if len(parts) != FIELDS:
            reasons.append(f"unreadable pre-push line '{shown(line)}'")
            continue
        _local_ref, local, remote_ref, _remote = parts
        if local.strip("0"):
            found = ref_problems(remote_ref)
            if found:
                reasons.append(describe("pushed ref", remote_ref, found))
    return reasons


def run(stdin: str) -> int:
    """Exit 1 refuses the push, 2 reports a fault in this check (the push is refused too), 0 lets it go."""
    try:
        reasons = refused(stdin.splitlines())
    except Exception as exc:  # noqa: BLE001 -- say what failed instead of a bare traceback
        print(
            f"refname-filename-metachar-pre-push: internal error ({type(exc).__name__}); push not checked",
            file=sys.stderr,
        )
        return 2
    for reason in reasons:
        print(f"BLOCKED: {reason}", file=sys.stderr)
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(run("" if sys.stdin.isatty() else sys.stdin.read()))

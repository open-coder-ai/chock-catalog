#!/usr/bin/env python3
"""Refuse a write that carries a Java construct a rule denies: staged at commit, or as it is written."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# The engine ships beside this script, so the gate needs nothing installed. A missing or
# broken copy raises here, and the runner treats an exit it did not ask for as a refusal:
# never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_security.decision import ASK, DENY, UNJUDGED, FileText
from chock_security.engine import evaluate
from chock_security.rules import registry
from chock_security.selection import SelectionError, load

ALLOW, REFUSE = 0, 1

#: A gate has no terminal: the runner speaks for a hook, a tool call, or a turn's end.
_NO_ONE_TO_ASK = (
    "chock-security: the finding(s) above are set to 'ask' and a gate has no terminal to ask. "
    "Refusing rather than allowing: an ask never degrades to an allow."
)


def main() -> int:
    payload = json.load(sys.stdin)
    root = Path(payload.get("repo_root") or ".")
    files = [FileText(path, text) for path, text in (payload.get("writes") or {}).items()]
    try:
        verdicts = load(root, registry())
    except SelectionError as exc:
        print(f"chock-security: {exc}", file=sys.stderr)
        return REFUSE
    try:
        findings = evaluate(files, verdicts)
    except Exception as exc:  # noqa: BLE001 -- any failure here refuses; it never falls through
        print(UNJUDGED.format(reason=f"{type(exc).__name__}: {exc}"), file=sys.stderr)
        return REFUSE
    for finding in findings:
        print(finding.render(), file=sys.stderr)
    if any(f.verdict == DENY for f in findings):
        return REFUSE
    if any(f.verdict == ASK for f in findings):
        print(_NO_ONE_TO_ASK, file=sys.stderr)
        return REFUSE
    return ALLOW


if __name__ == "__main__":
    sys.exit(main())

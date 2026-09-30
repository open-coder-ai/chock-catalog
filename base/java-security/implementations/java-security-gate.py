#!/usr/bin/env python3
"""Print the findings of a write -- staged at commit, or as it is written -- for the engine to compare."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# The engine ships beside this script, so the gate needs nothing installed. A missing or
# broken copy raises here, and the runner treats an exit it did not ask for as a refusal:
# never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_security.decision import ASK, DENY, UNJUDGED, FileText
from chock_security.document import document
from chock_security.engine import evaluate
from chock_security.rules import registry
from chock_security.selection import SelectionError, load

ALLOW, REFUSE = 0, 1

#: A gate has no terminal: the runner speaks for a hook, a tool call, or a turn's end.
_NO_ONE_TO_ASK = (
    "chock-security: the finding(s) above are set to 'ask' and a gate has no terminal to ask. "
    "Refusing rather than allowing: an ask never degrades to an allow."
)

#: Where the person committing reviews what is staged, so a waiver in it is theirs. Everywhere else
#: -- as the agent writes, and at its turn's end -- the text is the agent's own.
REVIEWED_EVENTS = frozenset({"commit", "push", "ci"})

HUMANS_WAIVE = (
    "java-security: a waiver ('// chock: allow <rule-id>' on the line) is a human reviewer's "
    "decision, never the agent's. In the agent it counts only once a human has committed it, and "
    "one the agent writes is refused. Change the code as the rule says, or stop and ask the user."
)


def committed(root: Path):
    """A path's text at HEAD, read from git in `root` for the waivers a human committed; None when there is none."""

    def read(path: str) -> str | None:
        rel = Path(path)
        if rel.is_absolute():
            try:
                rel = rel.resolve().relative_to(root.resolve())
            except ValueError:
                return None
        try:
            proc = subprocess.run(  # noqa: S603 -- a fixed git argv; the path is an argument, never a shell word
                ["git", "show", f"HEAD:{rel.as_posix()}"],  # noqa: S607 -- git from PATH, as the runner's own
                cwd=root,
                capture_output=True,
                check=False,
            )
        except OSError:  # no git on PATH, or no such directory: there is no committed text to read
            return None
        return proc.stdout.decode("utf-8-sig", errors="replace") if proc.returncode == 0 else None

    return read


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
        agent = payload.get("event") not in REVIEWED_EVENTS
        findings = evaluate(files, verdicts, committed(root) if agent else None)
    except Exception as exc:  # noqa: BLE001 -- any failure here refuses; it never falls through
        print(UNJUDGED.format(reason=f"{type(exc).__name__}: {exc}"), file=sys.stderr)
        return REFUSE
    # The engine runs this script again on the baseline text (`"baseline": true`) and keeps the keys the
    # write holds more of. Both runs judge with the same waivers, so a copy of a waived line is not new.
    print(json.dumps(document(findings, files)))
    for finding in findings:
        print(finding.render(), file=sys.stderr)
    if agent and findings:
        # Said on every refusal, not only after an attempt: several rules name the waiver as the
        # way out, and the agent reads that as leave to write it.
        print(HUMANS_WAIVE, file=sys.stderr)
    if any(f.verdict == DENY for f in findings):
        return REFUSE
    if any(f.verdict == ASK for f in findings):
        print(_NO_ONE_TO_ASK, file=sys.stderr)
        return REFUSE
    return ALLOW


if __name__ == "__main__":
    sys.exit(main())

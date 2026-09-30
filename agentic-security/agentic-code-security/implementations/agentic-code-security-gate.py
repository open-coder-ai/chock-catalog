#!/usr/bin/env python3
"""Print the agentic-code-security findings of a write -- staged at commit, or as the agent writes it."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# The engine ships beside this script, so the gate needs nothing installed. A missing or broken
# copy raises here, and the runner treats an exit it did not ask for as a refusal, never an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentic_gate.document import document
from agentic_gate.engine import evaluate
from agentic_gate.registry import registry
from agentic_gate.selection import SelectionError, load

ALLOW, REFUSE = 0, 1

#: Where the person committing reviews what is staged, so a waiver there is a human's. Everywhere else the
#: text is the agent's own. The engine keeps the findings a change adds; see agentic_gate.document.
HUMAN_EVENTS = frozenset({"commit", "push", "ci"})

UNJUDGED = (
    "agentic-code-security could not reach a decision ({reason}). Refusing rather than allowing what it never judged."
)
HUMANS_WAIVE = (
    "agentic-code-security: a waiver ('# chock: allow <rule-id>' or '// chock: allow <rule-id>' on the line) is a "
    "human reviewer's decision, never the agent's. In the agent it counts only once a human has committed it, and "
    "one the agent writes is refused. Change the code as the rule says, or stop and ask the user."
)


def committed(root: Path):
    """A path's text at HEAD, read from git in `root` for waivers and provenance; None when there is none."""

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
    try:
        verdicts = load(root, registry())
    except SelectionError as exc:
        print(f"agentic-code-security: {exc}", file=sys.stderr)
        return REFUSE
    human = payload.get("event") in HUMAN_EVENTS
    writes = payload.get("writes") or {}
    try:
        findings = evaluate(writes, verdicts, committed(root), human=human)
    except Exception as exc:  # noqa: BLE001 -- any failure here refuses; it never falls through
        print(UNJUDGED.format(reason=f"{type(exc).__name__}: {exc}"), file=sys.stderr)
        return REFUSE
    # The engine runs this script again on the baseline text (`"baseline": true`) and keeps the keys the
    # write holds more of. Both runs judge with the same waivers, so a copy of a waived line is not new.
    print(json.dumps(document(findings, writes)))
    for finding in findings:
        print(finding.render(), file=sys.stderr)
    if findings and not human:
        print(HUMANS_WAIVE, file=sys.stderr)
    return REFUSE if findings else ALLOW


if __name__ == "__main__":
    sys.exit(main())

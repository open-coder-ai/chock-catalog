#!/usr/bin/env python3
"""Ask when a change removes a check without a replacement in its hunk; block when it removes a mitigation."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from chock_scan.data_table import TableError
from diffshape import changes, judge, scope, shapes
from diffshape.hunks import Hunk, lines_of

HERE = Path(__file__).resolve().parent
BLOCK, ASK, UNJUDGED = 1, 3, 2
#: Events at which a person staged the text, so a pragma on a line counts. Anywhere else (the agent's tool
#: call, its turn's end, its commit) a pragma counts only once the same line is already committed.
HUMAN_EVENTS = frozenset({"commit", "push", "ci"})
STAGED_EVENTS = frozenset({"commit", "agent-commit"})
PRAGMA = re.compile(r"pragma:\s*allowlist\s+(guard-removal|mitigation-removal)\b", re.IGNORECASE)
WAIVER_NAMES = {judge.GUARD_RULE: "guard-removal", judge.MITIGATION_RULE: "mitigation-removal"}
MAX_CHANGED_LINES = 20000
SHOWN = 12
OVERSIZE = (
    "guard-deletion: the change is too large to read line by line (over {limit} changed lines in judged files), "
    "so it is not judged. A person decides: split the change, or confirm it."
)


def make_waiver(root: Path, event: str):
    """The waiver test for this event.

    A person's event honours the rule's pragma on any line of the hunk. Anywhere else only a removed line the
    finding rests on counts, and only if HEAD already holds that exact line: an added line can be a copy of one.
    """
    heads: dict[str, frozenset[str]] = {}

    def waived(hunk: Hunk, involved: list[str], rule: str) -> bool:
        def named(raw: str) -> bool:
            found = PRAGMA.search(raw)
            return bool(found) and found[1].lower() == WAIVER_NAMES[rule]

        if event in HUMAN_EVENTS:
            return any(named(raw) for raw in (*hunk.removed, *hunk.added))
        if hunk.path not in heads:
            heads[hunk.path] = frozenset(lines_of(changes.committed(root, hunk.path)))
        return any(named(raw) and raw in heads[hunk.path] for raw in involved)

    return waived


def collect(payload: dict, root: Path, event: str):
    """The hunks of the change this event is judging."""
    if event in STAGED_EVENTS:
        return changes.staged(root)
    if event == "ci":
        return changes.in_range(root)
    return changes.written(root, payload.get("writes") or {})


def report(findings: list[judge.Finding]) -> str:
    blocked = [f for f in findings if f.rule == judge.MITIGATION_RULE]
    asked = [f for f in findings if f.rule == judge.GUARD_RULE]
    out: list[str] = []
    if blocked:
        out.append("mitigation-removal: this change removes or weakens a security mitigation (refused):")
        out += [f"  {f.path}:{f.line}  {f.label} -- {f.advice}" for f in blocked[:SHOWN]]
    if asked:
        out.append(
            "guard-deletion: this change removes a check and puts none like it in the same hunk (asks a person):"
        )
        out += [f"  {f.path}:{f.line}  {f.label} -- {f.advice}" for f in asked[:SHOWN]]
    more = len(findings) - min(len(blocked), SHOWN) - min(len(asked), SHOWN)
    out += [f"  ... and {more} more"] if more > 0 else []
    out.append(
        "Keep the check or mitigation, or move it within the same hunk. A person who has reviewed the removal "
        "waives a line with 'pragma: allowlist guard-removal' or 'pragma: allowlist mitigation-removal' on it."
    )
    return "\n".join(out)


def main() -> int:
    """Exit 1 on a removed or weakened mitigation, 3 on a removed guard, 2 when the change cannot be judged."""
    try:
        payload = json.load(sys.stdin)
        root = Path(payload.get("repo_root") or ".")
        event = str(payload.get("event", ""))
        table = shapes.load(HERE / "data" / "shapes.json")
        in_scope = scope.load(HERE / "data" / "scope.json")
        hunks = [h for h in collect(payload, root, event) if scope.in_scope(h.path, in_scope)]
    except (TableError, changes.ChangeError, ValueError, AttributeError, TypeError) as exc:
        print(
            f"guard-deletion: could not read the change ({type(exc).__name__}: {exc}); refusing to guess",
            file=sys.stderr,
        )
        return UNJUDGED
    if sum(len(h.removed) + len(h.added) for h in hunks) > MAX_CHANGED_LINES:
        print(OVERSIZE.format(limit=MAX_CHANGED_LINES), file=sys.stderr)
        return ASK
    waived = make_waiver(root, event)
    findings = [f for h in hunks for f in judge.judge_hunk(h, table, waived)]
    if not findings:
        return 0
    print(report(findings), file=sys.stderr)
    return BLOCK if any(f.rule == judge.MITIGATION_RULE for f in findings) else ASK


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Report each broad IAM, RBAC or role grant in a write; the engine keeps the ones the change adds."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

# The scanners ship beside this script. A missing or broken copy raises here, and the runner
# treats an exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from iamscan.access import split_lines
from iamscan.files import scan_file
from iamscan.model import BLOCK, Finding
from iamscan.waivers import HUMAN_EVENTS, SidecarError, committed, pragma_waived, sidecar_waivers

ALLOW, REFUSE, ASK = 0, 1, 3

UNJUDGED = "iam-policy-scan could not reach a decision ({reason}). Refusing rather than allowing what it never judged."
HUMANS_WAIVE = (
    "iam-policy-scan: a waiver ('# pragma: allowlist broad-privilege' beside the grant, or an entry in "
    ".chock/iam-policy-scan.json) is a human reviewer's decision, never the agent's. In the agent it counts only once "
    "a human has committed it. Narrow the grant as the rule says, or stop and ask the user."
)


def document(findings: list[Finding]) -> dict[str, list[dict[str, object]]]:
    """The `{"findings": [...]}` the engine compares with the baseline run's: keyed by rule and statement, never by line."""
    return {
        "findings": [
            {"key": f.key, "path": f.path, "line": f.line, "message": f.render().split(": ", 1)[1]} for f in findings
        ]
    }


def judged(payload: dict) -> list[Finding]:
    root = Path(payload.get("repo_root") or ".")
    event = str(payload.get("event", ""))
    writes = {str(p).replace("\\", "/"): t for p, t in (payload.get("writes") or {}).items() if isinstance(t, str)}
    head = committed(root)
    spent: dict[str, Counter] = {}
    found = []
    for path in sorted(writes):
        lines = split_lines(writes[path])
        found += [f for f in scan_file(path, writes[path]) if not pragma_waived(f, lines, event, head, spent)]
    if not found:
        return []
    # The sidecar is read only when something needs it, so a broken one cannot refuse a write that holds no grant.
    waived = sidecar_waivers(event, writes, head)
    return [f for f in found if (f.path, f.rule, f.sig) not in waived]


def main() -> int:
    payload = json.load(sys.stdin)
    try:
        findings = judged(payload)
    except SidecarError as exc:
        print(f"iam-policy-scan: {exc}", file=sys.stderr)
        return REFUSE
    except Exception as exc:  # noqa: BLE001 -- any failure here refuses; it never falls through
        print(UNJUDGED.format(reason=f"{type(exc).__name__}: {exc}"), file=sys.stderr)
        return REFUSE
    print(json.dumps(document(findings)))
    for finding in findings:
        print(finding.render(), file=sys.stderr)
    if findings and payload.get("event") not in HUMAN_EVENTS:
        print(HUMANS_WAIVE, file=sys.stderr)
    if not findings:
        return ALLOW
    return REFUSE if any(f.tier == BLOCK for f in findings) else ASK


if __name__ == "__main__":
    sys.exit(main())

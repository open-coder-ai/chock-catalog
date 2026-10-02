#!/usr/bin/env python3
"""Print the secret-bearing files a write adds -- staged at commit, or as it is written -- for the engine to compare."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# The rules and their chock_scan copy ship beside this script. A missing or broken copy raises here,
# and the runner treats an exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sbf_core import BLOCK, Finding
from sbf_judge import judge

ALLOW, REFUSE, BAD_INPUT, ASK = 0, 1, 2, 3
ADVICE = (
    "scan-secret-files: keep the file out of the repository -- add it to .gitignore, load the value "
    "from the environment or a secret manager, and commit a template (.env.example, placeholders) "
    "instead. Rotate any credential that was written or pushed. No inline waiver: a person who has "
    "reviewed a fixture commits it from their own shell with CHOCK_ALLOW=scan-secret-files."
)


def row(path: str, finding: Finding) -> dict:
    """The engine's finding; its key is the rule and a hash of the flagged value, never the value or a line number."""
    digest = hashlib.sha256(finding.value.strip().encode("utf-8", "surrogatepass")).hexdigest()[:16]
    asks = " (asks)" if finding.level != BLOCK else ""
    return {
        "key": f"{finding.rule}|{digest}",
        "path": path,
        "line": finding.line,
        "message": f"{finding.rule}: {finding.what}{asks}",
        "rule": finding.rule,
    }


def findings(writes: dict[str, str]) -> tuple[list[dict], bool]:
    """Every finding of every written file, and whether any of them refuses outright."""
    rows, refuse = [], False
    for path, text in sorted(writes.items()):
        for finding in judge(path, text):
            rows.append(row(path, finding))
            refuse = refuse or finding.level == BLOCK
    return rows, refuse


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        print("scan-secret-files: stdin is not the gate JSON", file=sys.stderr)
        return BAD_INPUT
    writes = payload.get("writes") if isinstance(payload, dict) else None
    if not isinstance(writes, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in writes.items()):
        print("scan-secret-files: the gate JSON has no {path: text} writes", file=sys.stderr)
        return BAD_INPUT
    rows, refuse = findings(writes)
    print(json.dumps({"findings": rows}))
    if not rows:
        return ALLOW
    print("scan-secret-files: these files are secrets, or hold one (path:line):", file=sys.stderr)
    for item in rows:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(ADVICE, file=sys.stderr)
    return REFUSE if refuse else ASK


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Report each GitHub Actions weakness in a written workflow, composite action or Dependabot file; the engine keeps the new ones."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# The rules and the shared YAML scanner ship beside this script. A missing or broken copy raises
# here, and the runner treats an exit it did not ask for as undecided, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_scan import data_table
from ghascan.rules import BLOCK, RULES, UNREADABLE, hits_for, kind_of

TABLE = Path(__file__).resolve().parent / "ghascan" / "data" / "actions.json"
TABLE_KEYS = (
    "agent_actions",
    "cache_actions",
    "cache_default_on",
    "cache_input_actions",
    "publish_actions",
    "automerge_actions",
    "cloud_key_inputs",
)
WAIVER = re.compile(r"chock:\s*allow\s+(gha-[a-z-]+)")
FALSY = {"", "0", "false", "no", "off"}


def _lists(doc: dict) -> list[str]:
    bad = [k for k in TABLE_KEYS[:-1] if not all(isinstance(v, str) and v == v.lower() for v in doc[k])]
    inputs = doc["cloud_key_inputs"]
    if not all(isinstance(v, list) and all(isinstance(n, str) for n in v) for v in inputs.values()):
        bad.append("cloud_key_inputs")
    return [f"{k}: every entry must be a lower-case string" for k in bad]


def load_tables() -> dict:
    return data_table.load(TABLE, kind="curated", schema=1, keys=TABLE_KEYS, check=_lists)


def waivable(event: str) -> bool:
    """A waiver counts only at a person's commit; the engine passes an agent's commit as agent-commit."""
    agent = os.environ.get("CHOCK_AGENT_COMMIT", "").strip().lower() not in FALSY
    return event == "commit" and not agent


def findings(payload: dict, tables: dict) -> list[dict]:
    """Every hit in every in-scope write, keyed by rule, scope (job or file) and the flagged text, never a line."""
    waive = waivable(str(payload.get("event", "")))
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        norm = path.replace("\\", "/")
        kind = kind_of(norm)
        if kind is None or not isinstance(text, str):
            continue
        lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        for hit in sorted(hits_for(kind, text, tables), key=lambda h: (h.line, h.rule, h.detail)):
            line = lines[hit.line - 1] if 0 < hit.line <= len(lines) else ""
            if waive and hit.rule in WAIVER.findall(line):
                continue
            rule = RULES[hit.rule]
            item = {
                "key": f"{hit.rule}|{hit.scope}|{hit.detail}",
                "path": norm,
                "line": hit.line,
                "rule": hit.rule,
                "message": f"{hit.rule} ({rule.cwe}, {rule.cicd}): {hit.message}",
            }
            # An unreadable file hides whatever the change put in it, so a baseline that was already
            # unreadable never absolves it: the finding is new on every write of that file.
            if hit.rule == UNREADABLE and not payload.get("baseline"):
                item["new"] = True
            found.append(item)
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        tables = load_tables()
    except (json.JSONDecodeError, data_table.TableError) as exc:
        print(f"ci-github-actions-security: cannot judge ({exc})", file=sys.stderr)
        return 2
    found = findings(payload, tables)
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print("ci-github-actions-security: this change weakens a GitHub Actions workflow:", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        "Fix the workflow as each line says. A person who has reviewed one may keep it with "
        "'# chock: allow <rule id>' on that line and commit from their own shell; in the agent only a "
        "line already committed in HEAD counts.",
        file=sys.stderr,
    )
    return 1 if any(RULES[f["rule"]].tier == BLOCK for f in found) else 3


if __name__ == "__main__":
    sys.exit(main())

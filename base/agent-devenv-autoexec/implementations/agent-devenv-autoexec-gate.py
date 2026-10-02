#!/usr/bin/env python3
"""Report what a write makes a developer tool run on open, entry, start or clone; the engine keeps what a change adds."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# The rules ship beside this script. A missing or broken copy raises here, and the runner treats an
# exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from devenv.core import BLOCK, RULES, Collector
from devenv.paths import normalized
from devenv.scan import cross_references, judge_file, link_findings, raw_cr, symlinks, untracked

ALLOW, REFUSE, UNDECIDED, ASK = 0, 1, 2, 3
#: Where a person reviews what is committed or pushed; anywhere else a waiver counts only once committed.
HUMAN_EVENTS = frozenset({"commit", "push", "ci"})
AGENT_ENV = ("CHOCK_AGENT_COMMIT", "CLAUDECODE", "AI_AGENT")
FALSY = frozenset({"", "0", "false", "no", "off"})
#: A waiver counts only inside a comment, never inside a value such as a hook's command string.
_WAIVER = re.compile(r"(?:#|//|;|<!--|/\*)\s*chock:\s*allow\s+(dev-[a-z-]+)")


def by_person(event: str) -> bool:
    agent = any(os.environ.get(name, "").strip().lower() not in FALSY for name in AGENT_ENV)
    return event in HUMAN_EVENTS and not agent


def committed(root: Path, path: str) -> str:
    try:
        proc = subprocess.run(  # noqa: S603 -- a fixed git argv; the path is an argument, never a shell word
            ["git", "show", f"HEAD:./{path}"],  # noqa: S607 -- git from PATH, as the runner's own
            cwd=root,
            capture_output=True,
            check=False,
        )
    except OSError:
        return ""
    return proc.stdout.decode("utf-8", "replace") if proc.returncode == 0 else ""


def waived(c: Collector, rule: str, line: int, head: frozenset[str] | None) -> bool:
    """`chock: allow <rule>` in a comment on the finding's line or a comment line just above it.

    In the agent (`head` given) both the waiver line and the finding's line must already be committed, so
    a waiver cannot be moved onto a new value.
    """
    target = c.lines[line - 1] if 0 < line <= len(c.lines) else ""
    for number in (line, line - 1):
        text = c.lines[number - 1] if 0 < number <= len(c.lines) else ""
        own_line = number == line or text.lstrip().startswith(("#", "//", ";", "<!--", "/*"))
        committed = head is None or (text in head and target in head)
        if own_line and rule in _WAIVER.findall(text) and committed:
            return True
    return False


def findings(payload: dict) -> list[dict]:
    """Every finding in the write, keyed by rule, place and normalized value, never by line number."""
    event = str(payload.get("event", ""))
    root = Path(str(payload.get("repo_root") or "."))
    writes = {p: t for p, t in (payload.get("writes") or {}).items() if isinstance(t, str)}
    collectors = {path: c for path, text in sorted(writes.items()) if (c := judge_file(path, text)) is not None}
    added = {**(untracked(root) if event == "tool_use" else {}), **{normalized(p): t for p, t in writes.items()}}
    cross_references(collectors, added)
    if not payload.get("baseline"):
        extras = [link_findings(symlinks(root, event, writes)), raw_cr(root, event, writes)]
        for path, extra in [item for found in extras for item in found.items()]:
            collectors.setdefault(path, Collector(writes.get(path, ""))).found.extend(extra.found)
    person = by_person(event)
    found = []
    for path, c in sorted(collectors.items()):
        head = None
        if not person and _WAIVER.search(c.text):
            head = frozenset(committed(root, path).split("\n"))
        for item in sorted(set(c.found), key=lambda f: (f.line, f.rule, f.detail)):
            if _WAIVER.search(c.text) and waived(c, item.rule, item.line, head):
                continue
            pack = RULES[item.rule][0]
            found.append(
                {
                    "key": f"{item.rule}|{item.detail}",
                    "path": path.replace("\\", "/"),
                    "line": item.line,
                    "rule": item.rule,
                    "message": f"[{pack}/{item.rule}, {item.severity}] {item.message}",
                    "severity": item.severity,
                }
            )
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        found = findings(payload)
    except Exception as exc:  # noqa: BLE001 -- anything unexpected is undecided, which the runner refuses
        print(f"agent-devenv-autoexec could not reach a decision ({type(exc).__name__}: {exc}).", file=sys.stderr)
        return UNDECIDED
    print(json.dumps({"findings": [{k: v for k, v in f.items() if k != "severity"} for f in found]}))
    if not found:
        return ALLOW
    print("agent-devenv-autoexec: a write makes a developer tool run code or skip a check on its own:", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        "Files that run on open, clone, install or shell entry are changed by people. Remove the hook, task, helper, "
        "override or setting, or ask a person to review it; a reviewed line may carry 'chock: allow <rule-id>' "
        "where the file has comments, added by that person in their own commit.",
        file=sys.stderr,
    )
    return REFUSE if any(item["severity"] == BLOCK for item in found) else ASK


if __name__ == "__main__":
    sys.exit(main())

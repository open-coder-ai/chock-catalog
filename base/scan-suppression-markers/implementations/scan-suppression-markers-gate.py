#!/usr/bin/env python3
"""Report each scanner suppression marker in a write; the engine keeps the ones a change adds."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# The rule tables ship beside this script. A missing copy raises here, and the runner treats an
# exit it did not ask for as undecided, which takes the declared action: never an allow. No
# bytecode cache is written: the gate is read_only in the repository it judges.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from suppression_config import config_findings, normalized  # noqa: E402 -- after the path and cache setup
from suppression_markers import marker_rule  # noqa: E402

ALLOW, ASK, UNREADABLE = 0, 3, 2

#: Prose and chock's own managed files: a marker there silences no scanner.
PROSE = re.compile(
    r"(^|/)(CHANGELOG|CHANGES|HISTORY)[^/]*$|\.(md|mdx|markdown|rst|txt|adoc)$"
    r"|(^|/)\.agents/policies/|(^|/)\.chock/|(^|/)evals/suite\.ya?ml$",
    re.IGNORECASE,
)

ADVICE = (
    "Fix what the scanner reports instead of silencing it. If the finding is a reviewed false "
    "positive, a person keeps the marker by committing from their own shell with "
    "CHOCK_ALLOW=scan-suppression-markers set for that one commit; an agent asks the person."
)


def _finding(rule: str, path: str, number: int, detail: str, line: str) -> dict:
    return {
        "key": f"{rule}|{detail}",
        "path": path,
        "line": number,
        "rule": rule,
        "message": f"suppression marker ({rule}): {line.strip()[:120]}",
    }


def file_findings(path: str, text: str) -> list[dict]:
    """Every suppression marker, ignore entry and soft-failed scan in one file, keyed without line numbers."""
    if PROSE.search(path):
        return []
    lines = text.splitlines()
    found: dict[int, dict] = {}
    for rule, number, detail in config_findings(path, text):
        found.setdefault(number, _finding(rule, path, number, detail, lines[number - 1]))
    for number, line in enumerate(lines, 1):
        rule = None if number in found else marker_rule(line)
        if rule:
            found[number] = _finding(rule, path, number, normalized(line), line)
    return [found[number] for number in sorted(found)]


def findings(payload: dict) -> list[dict]:
    """The findings of every written file. The engine runs this again on the baseline text and asks
    only about the keys the change holds more of."""
    writes = payload.get("writes")
    if not isinstance(writes, dict):
        raise TypeError("writes")
    out: list[dict] = []
    for path, text in sorted(writes.items()):
        if isinstance(text, str):
            out += file_findings(str(path).replace("\\", "/"), text)
    return out


def main() -> int:
    try:
        found = findings(json.load(sys.stdin))
    except (ValueError, TypeError, AttributeError):
        print("scan-suppression-markers: stdin is not the gate JSON; cannot judge", file=sys.stderr)
        return UNREADABLE
    print(json.dumps({"findings": found}))
    if not found:
        return ALLOW
    print("scan-suppression-markers: this change adds a scanner suppression:", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(ADVICE, file=sys.stderr)
    return ASK


if __name__ == "__main__":
    sys.exit(main())

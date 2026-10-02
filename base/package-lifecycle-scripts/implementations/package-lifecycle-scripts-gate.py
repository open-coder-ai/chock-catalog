#!/usr/bin/env python3
"""Report each install- or build-time hook a write declares; the engine keeps the ones a change adds or changes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# The detectors ship beside this script. A missing or broken copy raises here, and the runner
# treats an exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lifecycle import ASK, BLOCK
from lifecycle.dispatch import read

SAY = {BLOCK: "fetch-exec class (would block)", ASK: "new or changed hook (would ask)"}


def findings(payload: dict) -> list[dict]:
    """Every hook in the written files, keyed by rule, entry, class and normalized value, never by line.

    The engine runs this again on the baseline text and refuses only the keys the change holds more
    of, so an untouched hook is old, an edited one is new, and a removed one is nothing.
    """
    writes = {str(p).replace("\\", "/"): t for p, t in (payload.get("writes") or {}).items() if isinstance(t, str)}
    root = str(payload.get("repo_root") or "")
    found = []
    for path, text in sorted(writes.items()):
        for hit in read(path, text, writes, root):
            found.append(
                {
                    "key": f"{hit.rule}|{hit.entry}|{hit.level}|{hit.value}",
                    "path": path,
                    "line": hit.line,
                    "rule": hit.rule,
                    "level": hit.level,
                    "message": f"{hit.rule} {hit.entry}: {hit.why} [{SAY[hit.level]}]"[:300],
                }
            )
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("package-lifecycle-scripts: stdin is not the gate JSON", file=sys.stderr)
        return 2
    found = findings(payload if isinstance(payload, dict) else {})
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print("package-lifecycle-scripts: a write declares code that runs at install or build time:", file=sys.stderr)
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        "Keep install and build steps offline and explicit: download to a file, verify its checksum, run it "
        "as a reviewed step, and pin git or URL dependencies to a commit. A person reviews any new hook.",
        file=sys.stderr,
    )
    # 1 refuses, 3 asks; the manifest's declared action (warn while observed) caps either.
    return 1 if any(item["level"] == BLOCK for item in found) else 3


if __name__ == "__main__":
    sys.exit(main())

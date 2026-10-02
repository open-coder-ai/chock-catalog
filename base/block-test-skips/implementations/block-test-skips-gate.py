#!/usr/bin/env python3
"""Report each test skip, focus marker or test-hiding runner option in a write; the engine keeps the ones a change adds."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path, PurePosixPath

# The detectors ship beside this script. A missing or broken copy raises here, and the runner
# treats an exit it did not ask for as a refusal, never as an allow.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from skipscan import CONFIG, SKIP
from skipscan.config import config_hits, config_kind
from skipscan.langs import EXTENSIONS, line_hits
from skipscan.pyrules import python_hits
from skipscan.scope import scopes_for

#: protect-test-integrity's test paths, kept identical; MORE_TEST_PATHS widens them for this gate.
TEST_PATH = re.compile(
    r"(^|/)(tests?/|__tests__/|test_[^/]*\.py$|[^/]*_test\.(py|go)$|[^/]*\.(test|spec)\.[cm]?[jt]sx?$|src/test/)"
)
MORE_TEST_PATHS = re.compile(
    r"(^|/)([Tt]ests?/|[Ss]pecs?/|e2e/|cypress/|playwright/|[^/]*_(spec|test)\.rb$|tests?\.py$|[^/]*\.Tests?/"
    r"|[^/]*Tests?\.(java|kt|kts|groovy|scala|cs|php|swift)$|[^/]*\.(test|spec)\.[^/.]+$)"
)
WAIVER = re.compile(r"chock:\s*allow\s+test-skip")
FALSY = {"", "0", "false", "no", "off"}
LABELS = {SKIP: "test skip or focus marker", CONFIG: "runner config that hides tests"}


def kind_of(path: str) -> str | None:
    """What a path is judged as: a runner config, a test file in some language, or nothing."""
    name = PurePosixPath(path).name
    suffix = PurePosixPath(path).suffix
    if kind := config_kind(name):
        return kind
    if name == "conftest.py":
        return "python"
    if suffix == ".rs":
        # `#[ignore]` means nothing outside a test, so every Rust file is judged, cfg(test) modules included.
        return "rust"
    if not (TEST_PATH.search(path) or MORE_TEST_PATHS.search(path)):
        return None
    return "python" if suffix == ".py" else EXTENSIONS.get(suffix, "legacy")


def hits_of(kind: str, text: str) -> list[tuple[int, str, str | None]]:
    if kind == "python":
        return python_hits(text)
    if kind.endswith("-config"):
        return config_hits(kind, text)
    return line_hits(kind, text)


def waivable(event: str) -> bool:
    """A waiver counts only at commit, and never for a commit an agent marked as its own."""
    agent = os.environ.get("CHOCK_AGENT_COMMIT", "").strip().lower() not in FALSY
    return event == "commit" and not agent


def findings(payload: dict) -> list[dict]:
    """Every skip, focus marker or test-hiding option in a write, keyed by rule, enclosing test and detail.

    The detail is the normalized line, or for a list entry the entry itself. The engine runs this
    again on the baseline text and refuses only the keys the change holds more of.
    """
    waive = waivable(str(payload.get("event", "")))
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        norm = path.replace("\\", "/")
        kind = kind_of(norm)
        if kind is None:
            continue
        lines = text.splitlines()
        scope = scopes_for(norm, text)
        for number, rule, detail in sorted(set(hits_of(kind, text)), key=lambda hit: (hit[0], hit[1], hit[2] or "")):
            line = lines[number - 1]
            if waive and WAIVER.search(line):
                continue
            key = f"{rule}|{scope(number)}|{detail or ' '.join(line.split())}"
            found.append({"key": key, "path": norm, "line": number, "message": f"{LABELS[rule]}: {line.strip()[:120]}"})
    return found


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("block-test-skips: stdin is not the gate JSON", file=sys.stderr)
        return 2
    found = findings(payload)
    print(json.dumps({"findings": found}))
    if not found:
        return 0
    print(
        "block-test-skips: a write skips, disables or focuses a test, or configures the runner to hide one:",
        file=sys.stderr,
    )
    for item in found:
        print(f"  {item['path']}:{item['line']}: {item['message']}", file=sys.stderr)
    print(
        "Fix the test or the code rather than skipping it. A reviewed skip needs a person to add "
        "'chock: allow test-skip' on the line and commit from their own shell; in the agent, or for "
        "an agent's commit, only a skip already committed in HEAD counts.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Report each test skip, focus marker or test-hiding runner option in a write; the engine keeps the ones a change adds."""

from __future__ import annotations

import ast
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

#: protect-test-integrity's test paths, kept identical; MORE_TEST_PATHS widens them for this gate.
TEST_PATH = re.compile(
    r"(^|/)(tests?/|__tests__/|test_[^/]*\.py$|[^/]*_test\.(py|go)$|[^/]*\.(test|spec)\.[cm]?[jt]sx?$|src/test/)"
)
MORE_TEST_PATHS = re.compile(
    r"(^|/)([Tt]ests?/|[Ss]pecs?/|e2e/|cypress/|playwright/|[^/]*_(spec|test)\.rb$"
    r"|[^/]*Tests?\.(java|kt|kts|groovy|scala|cs|php|swift)$|[^/]*\.(test|spec)\.[^/.]+$)"
)
WAIVER = re.compile(r"chock:\s*allow\s+test-skip")
#: A declaration a skip sits under: a class, method or function, or a describe/it/test block's title.
DECLARES = re.compile(
    r"\b(?:class|void|func|fun|fn|def|function|module|mod)\s+(?:\([^)]*\)\s*)?(\w+)"
    r"|\b(?:describe|context|it|test|specify)(?:\.\w+)?[\s(]\s*['\"`]([^'\"`]+)"
)
ANNOTATIONS = ("@", "#[", "[")
FALSY = {"", "0", "false", "no", "off"}
LABELS = {SKIP: "test skip or focus marker", CONFIG: "runner config that hides tests"}


def _python_scope(text: str, number: int) -> str | None:
    """Dotted names of the classes and functions holding a line, a decorator counting as its function's."""
    try:
        parsed = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    holders = [
        (min([n.lineno, *(d.lineno for d in n.decorator_list)]), n.end_lineno or n.lineno, n.name)
        for n in ast.walk(parsed)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
    ]
    return ".".join(name for start, end, name in sorted(holders) if start <= number <= end)


def _declared(line: str) -> str | None:
    """The test or class a line declares, if it does."""
    found = DECLARES.search(line)
    return next((group for group in found.groups() if group), None) if found else None


def _outline_scope(lines: list[str], index: int) -> str:
    """Names of the declarations around a line that are indented less than it; an annotation names what it marks."""
    names: list[str] = []
    if lines[index].lstrip().startswith(ANNOTATIONS):
        below = next((line for line in lines[index + 1 :] if not line.lstrip().startswith(ANNOTATIONS)), "")
        names.append(_declared(below) or "")
    limit = len(lines[index]) - len(lines[index].lstrip())
    for line in reversed(lines[:index]):
        indent = len(line) - len(line.lstrip())
        if line.strip() and indent < limit and (name := _declared(line)):
            names.insert(0, name)
            limit = indent
    return ".".join(name for name in names if name)


def scope_of(path: str, text: str, number: int) -> str:
    """The test function or class a line sits in: from the syntax tree for Python, from indentation elsewhere."""
    if path.endswith(".py") and (named := _python_scope(text, number)) is not None:
        return named
    return _outline_scope(text.splitlines(), number - 1)


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
        for number, rule, detail in sorted(set(hits_of(kind, text)), key=lambda hit: (hit[0], hit[1], hit[2] or "")):
            line = lines[number - 1]
            if waive and WAIVER.search(line):
                continue
            key = f"{rule}|{scope_of(norm, text, number)}|{detail or ' '.join(line.split())}"
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

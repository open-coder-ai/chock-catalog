#!/usr/bin/env python3
"""Report each test skip or focus marker in a written test file; the engine keeps the ones a change adds."""

from __future__ import annotations

import ast
import json
import os
import re
import sys

TEST_PATH = re.compile(
    r"(^|/)(tests?/|__tests__/|test_[^/]*\.py$|[^/]*_test\.(py|go)$|[^/]*\.(test|spec)\.[cm]?[jt]sx?$|src/test/)"
)
SKIP = re.compile(
    r"@pytest\.mark\.skip\b|@pytest\.mark\.skipif\b|@unittest\.skip|\b(it|describe|test)\.skip\("
    r"|\bx(it|describe)\(|\b(it|describe|test)\.only\(|@Disabled\b|@Ignore\b|\bt\.Skip(Now|f)?\("
)
WAIVER = re.compile(r"chock:\s*allow\s+test-skip")
#: A declaration a skip sits under: a class, a Java or Go test method, or a JS describe/it/test block's title.
DECLARES = re.compile(
    r"\b(?:class|void|func)\s+(?:\([^)]*\)\s*)?(\w+)|\b(?:describe|it|test)(?:\.\w+)?\(\s*['\"`]([^'\"`]+)"
)
COMMENT_PREFIXES = ("#", "//", "*", "/*")
FALSY = {"", "0", "false", "no", "off"}


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
    if lines[index].lstrip().startswith("@"):
        below = next((line for line in lines[index + 1 :] if not line.lstrip().startswith("@")), "")
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


def waivable(event: str) -> bool:
    """A waiver counts only at commit, and never for a commit an agent marked as its own."""
    agent = os.environ.get("CHOCK_AGENT_COMMIT", "").strip().lower() not in FALSY
    return event == "commit" and not agent


def findings(payload: dict) -> list[dict]:
    """Every skip or focus marker in a written test file, keyed by rule, enclosing test and normalized line.

    The engine runs this again on the baseline text and refuses only the keys the change holds more of.
    """
    waive = waivable(str(payload.get("event", "")))
    found = []
    for path, text in sorted(payload.get("writes", {}).items()):
        norm = path.replace("\\", "/")
        if not TEST_PATH.search(norm):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith(COMMENT_PREFIXES) or not SKIP.search(line):
                continue
            if waive and WAIVER.search(line):
                continue
            key = f"test-skip|{scope_of(norm, text, number)}|{' '.join(line.split())}"
            message = f"test skip or focus marker: {line.strip()[:120]}"
            found.append({"key": key, "path": norm, "line": number, "message": message})
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
    print("block-test-skips: a test file holds a test skip or focus marker:", file=sys.stderr)
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

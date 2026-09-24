"""Repository-wide coding standards, mechanically enforced -- the framework's, applied here."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_LINES = 300
CODE_SUFFIXES = {".py", ".sh"}
SKIP_DIRS = {".git", ".framework", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv", "node_modules"}
# .chock/bin/ is the engine bundle chock writes, and .agents/ the copies of base/ policies this
# repository runs on itself; both are reviewed at their sources.
EXEMPT_PREFIXES = (".chock/bin/", ".agents/")
# TODO(lint-adoption): code that predates this budget, left whole rather than split under an
# unrelated change; each goes with the next change to its own policy or tool. Never add to this.
BASELINE = {
    "base/block-destructive-commands/implementations/block-destructive.sh",
    "base/no-a11y-regression/implementations/no-a11y-regression-pre-commit.py",
    "base/rtk-dangerous-actions-blocker/implementations/rtk-dangerous-actions-blocker.sh",
    "tools/check_a11y_rules.py",
}


def test_no_code_file_exceeds_the_review_budget() -> None:
    over = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT).as_posix()
        if not path.is_file() or path.suffix not in CODE_SUFFIXES or set(path.parts) & SKIP_DIRS:
            continue
        if rel in BASELINE or rel.startswith(EXEMPT_PREFIXES):
            continue
        count = len(path.read_text(encoding="utf-8").splitlines())
        if count > MAX_LINES:
            over.append(f"{rel}: {count} lines")
    assert not over, "Files exceed the 300-line review budget (split by activity):\n" + "\n".join(over)


def test_the_baseline_only_shrinks() -> None:
    still_over = {rel for rel in BASELINE if len((ROOT / rel).read_text(encoding="utf-8").splitlines()) > MAX_LINES}
    assert still_over == BASELINE, f"no longer over budget, remove from BASELINE: {sorted(BASELINE - still_over)}"

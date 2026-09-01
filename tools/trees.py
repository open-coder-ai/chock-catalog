"""The single list of published policy trees."""

from __future__ import annotations

from pathlib import Path

TREES = ("base", "compliance", "agentic-security")

ROOT = Path(__file__).resolve().parents[1]


def policy_dirs(root: Path = ROOT) -> list[Path]:
    """Every published policy folder, across all trees, sorted per tree."""
    found: list[Path] = []
    for tree in TREES:
        tree_root = root / tree
        if tree_root.is_dir():
            found += sorted(p for p in tree_root.iterdir() if p.is_dir())
    return found


if __name__ == "__main__":
    print("\n".join(TREES))

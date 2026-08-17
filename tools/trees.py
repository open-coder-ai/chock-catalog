"""The single list of published policy trees.

`base` is agent hygiene, which applies to any repo; `compliance` is jurisdiction-specific
and adopted deliberately; `agentic-security` earns its place only if the repo builds
agentic systems rather than merely uses one. All are published on the same terms:
validated, replayed, registered, packaged, documented.

Every consumer imports this list rather than carrying its own. The plugin check missed the
whole `compliance/` tree the day it was added, because its coverage was an enumerated
argument in CI rather than a discovery -- silent under-coverage that read as "checked
everything". A new tree added here is picked up by every tool and CI step at once; a tree
added anywhere else is the same bug again.
"""

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
    # `python tools/trees.py` prints the tree names, one per line, for shell consumers.
    print("\n".join(TREES))

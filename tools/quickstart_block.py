#!/usr/bin/env python3
"""Print the first ```bash fence under README.md's `## Quick start` heading.

CI pipes this straight into `bash -euo pipefail` in a throwaway directory, so the README's
own quick-start snippet is proven to run rather than merely read as plausible.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

HEADING = re.compile(r"^## Quick start\s*$", re.MULTILINE)
BASH_FENCE = re.compile(r"```bash\n(.*?)```", re.DOTALL)


def quickstart_block(text: str) -> str:
    """The content of the first ```bash fence after `## Quick start`, or raise."""
    heading = HEADING.search(text)
    if not heading:
        raise ValueError("README.md has no '## Quick start' heading")
    fence = BASH_FENCE.search(text, heading.end())
    if not fence:
        raise ValueError("no ```bash fence found after '## Quick start'")
    return fence.group(1)


def main() -> int:
    """Print the block to stdout, or fail loudly if the README no longer has one."""
    try:
        block = quickstart_block(README.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"quickstart_block: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(block)
    return 0


if __name__ == "__main__":
    sys.exit(main())

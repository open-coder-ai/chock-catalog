#!/usr/bin/env python3
"""Generate docs/quickstart.sh from README.md's Quick start block."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from quickstart_block import quickstart_block

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DEST = ROOT / "docs" / "quickstart.sh"

HEADER = (
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "# Generated from README.md's Quick start block by tools/gen_quickstart_sh.py -- "
    "do not edit by hand.\n\n"
)


def render() -> str:
    """The full contents of docs/quickstart.sh."""
    return HEADER + quickstart_block(README.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate docs/quickstart.sh.")
    parser.add_argument("--check", action="store_true", help="Fail if the script is out of date.")
    args = parser.parse_args(argv)

    script = render()
    if args.check:
        if not DEST.exists() or DEST.read_text(encoding="utf-8") != script:
            print(f"{DEST.relative_to(ROOT).as_posix()} is out of date.")
            print("Run `python tools/gen_quickstart_sh.py` and commit the result.")
            return 1
        print("docs/quickstart.sh matches README.md's Quick start block.")
        return 0

    DEST.write_text(script, encoding="utf-8", newline="\n")
    DEST.chmod(0o755)
    print(f"Wrote {DEST.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

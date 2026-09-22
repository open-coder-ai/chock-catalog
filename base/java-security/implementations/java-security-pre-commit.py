#!/usr/bin/env python3
"""Refuse a commit whose staged Java, template or config carries a construct a rule denies."""

from __future__ import annotations

import sys
from pathlib import Path

# The engine ships beside this script, so the hook needs nothing installed. A missing or
# broken copy raises here, and an exception is a non-zero exit: the commit is refused, never
# let through by a guard that could not judge it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from chock_security.frontends.precommit import main  # noqa: E402 -- resolves through the path above

if __name__ == "__main__":
    sys.exit(main())

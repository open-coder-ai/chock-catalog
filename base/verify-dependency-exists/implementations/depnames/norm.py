"""Name normalisation per ecosystem, so one allowlist line covers every spelling the ecosystem treats as one."""

from __future__ import annotations

import re

_PYTHON_SEPARATORS = re.compile(r"[-_.]+")


def normalize(eco: str, name: str) -> str:
    """PEP 503 for Python, `-`/`_` equivalence for Cargo, lowercase (scope kept) for the rest."""
    name = name.strip().lower()
    if eco == "py":
        return _PYTHON_SEPARATORS.sub("-", name)
    if eco == "cargo":
        return name.replace("_", "-")
    return name

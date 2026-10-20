"""Name normalisation per ecosystem, so one allowlist line covers every spelling the ecosystem treats as one."""

from __future__ import annotations

import re

_PYTHON_SEPARATORS = re.compile(r"[-_.]+")
#: Registries that cannot tell `Foo` from `foo`. Maven coordinates, Go module paths, Hex and pub names are
#: case-sensitive: `github.com/BurntSushi/toml` and `github.com/burntsushi/toml` are two modules.
_CASE_INSENSITIVE = frozenset({"py", "npm", "cargo", "gem", "composer", "nuget", "swift"})


def normalize(eco: str, name: str) -> str:
    """PEP 503 for Python, `-`/`_` equivalence for Cargo, lowercase for the case-blind registries, as written otherwise."""
    name = name.strip()
    if eco not in _CASE_INSENSITIVE:
        return name
    name = name.lower()
    if "://" in name:
        return name
    if eco == "py":
        return _PYTHON_SEPARATORS.sub("-", name)
    return name.replace("_", "-") if eco == "cargo" else name

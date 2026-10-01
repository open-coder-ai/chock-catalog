"""The constants a file declares as allowlists: `static final`, from an immutable factory, never mutated."""

from __future__ import annotations

import re

_IMMUTABLE = re.compile(
    r"\b(?:static\s+final|final\s+static)\b[^=;]*?(?<![\w$])([A-Z][A-Z0-9_]*)\s*=\s*"
    r"(?:(?:Map|Set|List)\s*\.\s*(?:of|ofEntries|copyOf)\s*\(|Immutable\w+\s*\.\s*(?:of|copyOf)\s*\("
    r"|Collections\s*\.\s*unmodifiable\w+\s*\(\s*(?![A-Za-z_$][\w$]*\s*\)))"
)
_MUTATORS = r"(?:put\w*|add\w*|remove\w*|retainAll|clear|compute\w*|merge|replace\w*|set|sort)"


def immutable_constants(code: str) -> frozenset[str]:
    """Constants this file declares `static final` from an immutable factory and never mutates."""
    names = {m[1] for m in _IMMUTABLE.finditer(code)}
    return frozenset(n for n in names if not re.search(rf"(?<![\w$]){n}\s*\.\s*{_MUTATORS}\s*\(", code))

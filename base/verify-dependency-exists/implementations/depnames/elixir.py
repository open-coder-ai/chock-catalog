"""mix.exs: the tuples of the deps function, read as text; Elixir is code, so only that literal form is read."""

from __future__ import annotations

import re

_DEPS = re.compile(r"^(\s*)defp?\s+deps\b[^\n]*\bdo\s*$")
_TUPLE = re.compile(r"\{\s*:([A-Za-z_][A-Za-z0-9_]*)\s*,")


def mix_names(text: str) -> list[str]:
    """Package atoms of `{:name, ...}` tuples between `defp deps do` and its closing `end`."""
    names: list[str] = []
    indent: str | None = None
    for line in text.removeprefix("\ufeff").splitlines():
        if indent is None:
            if m := _DEPS.match(line):
                indent = m.group(1)
        elif line.rstrip() == f"{indent}end":
            indent = None
        elif not line.lstrip().startswith("#"):
            names += _TUPLE.findall(line)
    return names

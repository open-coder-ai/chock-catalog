"""mix.exs: dependency tuples read as text; Elixir is code, so only the literal `{:name, "req" | opts}` form is read."""

from __future__ import annotations

import re

_COMMENT = re.compile(r"(?m)^[ \t]*#.*$")
_TUPLE = re.compile(r'\{\s*:([A-Za-z_][A-Za-z0-9_]*)\s*,\s*((?:"|[a-z_]+:)[^}]*)')
_HEX = re.compile(r"\bhex:\s*:([A-Za-z_][A-Za-z0-9_]*)")
_NOT_PACKAGES = frozenset({"ok", "error"})


def _local(rest: str) -> bool:
    """An umbrella sibling or a path dependency: no registry or git source is named."""
    return "in_umbrella:" in rest or (
        "path:" in rest and not re.search(r"\b(?:git|github|hex|organization)\b:|^\s*\"", rest)
    )


def mix_names(text: str) -> list[str]:
    """Atoms of `{:name, "~> 1"}` and `{:name, github: "x/y"}` tuples anywhere in the file, on one line or several.

    The whole file is read rather than a `deps` function, so a one-line `defp deps, do: [...]`, a multi-line tuple and
    an inline `deps: [...]` are all seen; `{:ok, "..."}` and `{:error, "..."}` results are not packages.
    """
    code = _COMMENT.sub("", text.removeprefix("﻿"))
    found = [(name, rest) for name, rest in _TUPLE.findall(code) if name not in _NOT_PACKAGES and not _local(rest)]
    return [(_HEX.search(rest) or [None, name])[1] for name, rest in found]

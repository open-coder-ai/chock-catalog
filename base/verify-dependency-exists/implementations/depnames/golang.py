"""go.mod: require directives and the module a replace points at."""

from __future__ import annotations

import re

_OPEN = re.compile(r"^(require|replace)\s*\(\s*$")
_LINE = re.compile(r"^(require|replace)\s+([^\s(].*)$")


def _module(token: str) -> str:
    return token.strip().strip('"`')


def _name(kind: str, spec: str) -> str | None:
    """The module a require line names, or the target of a replace; None for a local-path replace."""
    if kind == "require":
        parts = spec.split()
        return _module(parts[0]) if parts else None
    if "=>" not in spec:
        return None
    target = spec.split("=>", 1)[1].split()
    if not target or target[0].startswith((".", "/", "\\")) or re.match(r"^[A-Za-z]:", target[0]):
        return None
    return _module(target[0])


def go_mod_names(text: str) -> list[str]:
    """Module paths from single-line and block `require`, and non-local `replace` targets."""
    names: list[str] = []
    block: str | None = None
    for raw in text.removeprefix("\ufeff").splitlines():
        line = raw.split("//", 1)[0].strip()
        if block is not None:
            if line == ")":
                block = None
                continue
            kind, spec = block, line
        elif m := _OPEN.match(line):
            block = m.group(1)
            continue
        elif m := _LINE.match(line):
            kind, spec = m.group(1), m.group(2)
        else:
            continue
        if name := _name(kind, spec):
            names.append(name)
    return names

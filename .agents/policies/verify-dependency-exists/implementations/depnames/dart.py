"""pubspec.yaml: dependency keys, read with the shared YAML path scanner."""

from __future__ import annotations

from chock_scan import yamlpath

_SECTIONS = frozenset({"dependencies", "dev_dependencies", "dependency_overrides"})
_NAME_DEPTH = 2
_SDK_DEPTH = 3


def pubspec_names(text: str) -> list[str]:
    """Package names under dependencies, dev_dependencies and dependency_overrides; SDK entries (flutter) are skipped.

    A YAML stream the scanner refuses raises yamlpath.ParseError, so the caller reports it instead of guessing.
    """
    nodes = yamlpath.scan(text)
    for section in _SECTIONS:
        if yamlpath.unknown(nodes, (section,)):
            msg = f"{section} uses an alias, a merge key or a repeated key, which a loader may resolve to other names"
            raise yamlpath.ParseError(msg, 1)
    sdk = {
        n.path[:_NAME_DEPTH]
        for n in nodes
        if len(n.path) == _SDK_DEPTH and n.path[0] in _SECTIONS and n.path[2] == "sdk"
    }
    return [
        str(n.path[1])
        for n in nodes
        if len(n.path) == _NAME_DEPTH and n.path[0] in _SECTIONS and n.path not in sdk and isinstance(n.path[1], str)
    ]

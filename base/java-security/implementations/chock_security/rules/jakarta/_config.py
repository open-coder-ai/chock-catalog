"""Shared config-key reading for the jakarta pack: flattened `a.b=v` and nested YAML.

Every rule in this pack that reads a Quarkus/Micronaut key goes through here, so the two forms
(`.properties` and nested `.yml`) are read once, the same way, rather than each rule growing its
own string search that drifts from the next rule's.
"""

from __future__ import annotations

from collections.abc import Iterator

from chock_security.decision import FileText

#: Spring's own pack owns Spring code; this pack must not fire where a file carries it.
_SPRING_MARKER = "org.springframework"


def not_spring(text: FileText) -> bool:
    """True unless this file imports Spring -- the boundary every rule in this pack checks first."""
    return not text.holds(_SPRING_MARKER)


def flat_value(text: FileText, dotted_key: str) -> Iterator[tuple[int, str, str]]:
    """`key=value` lines, the flattened spelling `.properties` files (and some YAML) use."""
    for line_no, line in enumerate(text.lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        if key.strip() == dotted_key:
            yield line_no, line, value.strip().strip('"').strip("'")


def yaml_value(text: FileText, dotted_key: str) -> Iterator[tuple[int, str, str]]:
    """The value at a dotted path in nested YAML, found by indentation, not by string search.

    `a.b.c` matches a `c:` line only inside the block a sibling `b:` opened inside a `a:` block
    -- the same key spelled at a different nesting, or mentioned in a comment, is not this
    setting. Conservative: a file that never opens the path yields nothing.
    """
    segments = dotted_key.split(".")
    open_indent: dict[int, int] = {}
    depth = 0
    for line_no, line in enumerate(text.lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        indent = len(line) - len(line.lstrip(" "))
        while depth > 0 and indent <= open_indent.get(depth - 1, -1):
            depth -= 1
        key_part, sep, rest = stripped.partition(":")
        if not sep:
            continue
        key_part = key_part.strip().strip('"').strip("'")
        if depth < len(segments) and key_part == segments[depth]:
            if depth == len(segments) - 1:
                yield line_no, line, rest.strip().strip('"').strip("'")
                depth = 0
                open_indent.clear()
            else:
                open_indent[depth] = indent
                depth += 1

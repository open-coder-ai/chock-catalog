"""Reading a parsed policy without trusting the case of its keys."""

from __future__ import annotations

from collections.abc import Iterator


def entries(node: dict, name: str) -> list:
    """Every value stored under `name`, whatever the key's case (loaders differ, so every spelling counts)."""
    return [v for k, v in node.items() if isinstance(k, str) and k.lower() == name]


def literals(values: object) -> list[str]:
    """The strings in a value or a list of values; a reference (`!Ref`) or anything computed is not one."""
    if isinstance(values, str):
        return [] if getattr(values, "ref", False) else [str(values)]
    if isinstance(values, list | tuple):
        return [s for v in values for s in literals(v)]
    return []


def strings_of(node: dict, name: str) -> list[str]:
    return [s.strip() for s in literals(entries(node, name))]


def key_names(value: object) -> Iterator[str]:
    """Every mapping key at any depth, lower-cased: the condition keys a Condition block names."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k).lower()
            yield from key_names(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from key_names(v)

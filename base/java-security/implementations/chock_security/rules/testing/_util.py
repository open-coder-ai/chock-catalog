"""Shared helpers for the testing pack's own rules."""

from __future__ import annotations


def is_test_path(path: str, facts: dict) -> bool:
    """A file under a `src/test/` tree, or named like a test class, is where these rules apply."""
    return facts["dir_marker"] in path or path.endswith(tuple(facts["name_suffixes"]))


def holds(text: str, tokens: list[str]) -> bool:
    """Whether any of these tokens appears anywhere in `text`."""
    return any(token in text for token in tokens)

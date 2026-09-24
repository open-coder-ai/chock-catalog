"""Shared path check for the style pack's own rules: is this file a test file?"""

from __future__ import annotations


def is_test_path(path: str, facts: dict) -> bool:
    """A file under a `src/test/` tree, or named like a test class, is not production code."""
    return facts["dir_marker"] in path or path.endswith(tuple(facts["name_suffixes"]))

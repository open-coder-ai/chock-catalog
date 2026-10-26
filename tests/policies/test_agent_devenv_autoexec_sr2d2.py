"""agent-devenv-autoexec: long values and digests are keyed by their full digest."""

from __future__ import annotations

import re

from policies import devenvkit

core = devenvkit.gate.sys.modules["devenv.core"]
scan = devenvkit.gate.sys.modules["devenv.scan"]


def test_a_long_value_key_carries_the_full_digest() -> None:
    assert re.fullmatch(r"a{160}\.\.\.#[0-9a-f]{64}", core.norm("a" * 200))


def test_a_parsed_value_digest_is_the_full_digest() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", core.digest({"a": [1, 2]}))


def test_an_unreadable_file_key_carries_the_full_digest() -> None:
    keys = devenvkit.keys(".devcontainer/devcontainer.json", "{ not json")
    assert keys
    assert all(re.search(r"[0-9a-f]{64}$", key) for key in keys if "unreadable#" in key)
    assert any("unreadable#" in key for key in keys)

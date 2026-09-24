"""The registry: every pack ships rules, and every rule carries the texts the page and agent read."""

from __future__ import annotations

import pytest
from chock_security.rules import packs, registry
from chock_security.selection import LEGACY_RULES

RULES = registry()


@pytest.mark.parametrize("pack_id", sorted(packs()))
def test_pack_ships_rules_and_says_what_it_covers(pack_id: str) -> None:
    pack = packs()[pack_id]
    assert any(r.pack == pack_id for r in RULES.values()), f"pack {pack_id!r} ships no rule"
    assert pack.title
    assert pack.covers


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_carries_its_texts_and_its_pack_name(rule_id: str) -> None:
    rule = RULES[rule_id]
    for field in ("title", "constraint", "refuses", "silent_on"):
        assert getattr(rule, field), f"{rule_id} has no {field}"
    assert rule.suffixes, f"{rule_id} reads no file type"
    assert rule_id in LEGACY_RULES or rule_id.startswith(f"{rule.pack}-"), f"{rule_id} must be named '{rule.pack}-...'"

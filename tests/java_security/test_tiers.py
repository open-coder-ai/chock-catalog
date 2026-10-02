"""What silence means per tier: a security rule nobody spoke for denies; a quality rule allows (D2)."""

from __future__ import annotations

import pytest
from chock_security.decision import ALLOW, DENY
from chock_security.pack import Rule
from chock_security.rules import packs, registry
from chock_security.selection import SILENT, default

RULES = registry()
PACKS = packs()

#: Every quality pack, pinned: relabelling a pack to quality turns its rules off by default, so
#: it must change this line, in review, never only a `kind=` in the pack.
QUALITY_PACKS = frozenset({"bugs", "concurrency", "resources", "exceptions", "performance", "style", "testing"})
#: The rule count per quality pack, pinned for the same reason: a rule moved in turns off by default.
QUALITY_COUNTS = {"bugs": 12, "concurrency": 7, "resources": 5, "exceptions": 6, "performance": 5, "style": 9, "testing": 6}
SECURITY_RULES = 79


def test_every_pack_names_a_kind_with_a_written_default() -> None:
    assert {pack.kind for pack in PACKS.values()} <= set(SILENT)
    assert SILENT["security"] == DENY


def test_the_quality_packs_are_exactly_the_pinned_ones() -> None:
    assert {pid for pid, pack in PACKS.items() if pack.kind == "quality"} == QUALITY_PACKS
    counts = {pid: sum(1 for r in RULES.values() if r.pack == pid) for pid in QUALITY_PACKS}
    assert counts == QUALITY_COUNTS
    assert sum(QUALITY_COUNTS.values()) == 50


def test_every_security_rule_defaults_to_deny_and_every_quality_rule_to_allow() -> None:
    by_tier: dict[str, set[str]] = {}
    for rule_id, rule in RULES.items():
        tier = PACKS[rule.pack].kind
        by_tier.setdefault(tier, set()).add(default(rule))
        if tier == "security":
            assert default(rule) == DENY, f"{rule_id} is security-tier and must default to deny"
    assert by_tier == {"security": {DENY}, "quality": {ALLOW}}
    assert sum(1 for r in RULES.values() if PACKS[r.pack].kind == "security") == SECURITY_RULES


@pytest.mark.parametrize("kind", ["Quality", "", "audit-ish", "advisory"])
def test_a_kind_without_a_written_default_denies(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    import chock_security.selection as selection

    rule = next(r for r in RULES.values() if r.pack == "bugs")
    monkeypatch.setattr(selection, "_kind_of", lambda _pack: kind)
    assert selection.default(rule) == DENY


def test_a_rule_in_a_pack_this_build_does_not_carry_denies() -> None:
    stray = Rule(id="stray", pack="no-such-pack", title="t", suffixes=(".java",), scan=lambda _t: iter(()))
    assert default(stray) == DENY

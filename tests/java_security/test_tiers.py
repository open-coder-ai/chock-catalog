"""What silence means per tier: a security rule nobody spoke for denies; a quality rule allows (D2)."""

from __future__ import annotations

import pytest
from chock_security import selection
from chock_security.decision import ALLOW, DENY
from chock_security.pack import Rule
from chock_security.rules import packs, registry
from chock_security.selection import SILENT, default

RULES = registry()
PACKS = packs()

#: Every quality pack, pinned: relabelling a pack to quality turns its rules off by default, so
#: it must change this line, in review, never only a `kind=` in the pack.
QUALITY_PACKS = frozenset({"bugs", "concurrency", "resources", "exceptions", "performance", "style", "testing"})
#: Every quality rule, pinned for the same reason: a rule moved or swapped in turns off by default.
QUALITY_RULES = frozenset(
    {
        "bugs-string-identity-comparison",
        "bugs-equals-without-hashcode",
        "bugs-equals-non-object-parameter",
        "bugs-bigdecimal-double-constructor",
        "bugs-nan-comparison",
        "bugs-ignored-return-value",
        "bugs-boolean-assignment-in-condition",
        "bugs-array-tostring",
        "bugs-thread-run-instead-of-start",
        "bugs-self-assignment",
        "bugs-math-abs-of-hashcode-or-random",
        "bugs-integer-division-to-double",
        "concurrency-static-date-format",
        "concurrency-double-checked-locking",
        "concurrency-synchronization-on-shared-lock",
        "concurrency-empty-synchronized-block",
        "concurrency-wait-not-in-loop",
        "concurrency-sleep-in-synchronized",
        "concurrency-notify-instead-of-notifyall",
        "resources-unclosed-closeable",
        "resources-finalize-override",
        "resources-forced-gc",
        "resources-system-exit",
        "resources-run-finalizers-on-exit",
        "exceptions-empty-catch",
        "exceptions-catch-broad",
        "exceptions-catch-npe",
        "exceptions-finally-control-flow",
        "exceptions-generic-thrown",
        "exceptions-lost-cause",
        "performance-boxing-constructor",
        "performance-string-concat-loop",
        "performance-map-keyset-get",
        "performance-size-check",
        "performance-legacy-collection",
        "style-redundant-import",
        "style-system-out-println",
        "style-boolean-literal-comparison",
        "style-empty-statement",
        "style-type-name",
        "style-constant-name",
        "style-multiple-variable-declarations",
        "style-upper-ell",
        "style-array-type-style",
        "testing-no-assertion",
        "testing-thread-sleep",
        "testing-disabled-without-reason",
        "testing-asserttrue-equality",
        "testing-assertfalse-equals",
        "testing-assertequals-literal-actual",
    }
)
SECURITY_RULES = 79


def test_every_pack_names_a_kind_with_a_written_default() -> None:
    assert {pack.kind for pack in PACKS.values()} <= set(SILENT)
    assert SILENT["security"] == DENY


def test_the_quality_packs_are_exactly_the_pinned_ones() -> None:
    assert {pid for pid, pack in PACKS.items() if pack.kind == "quality"} == QUALITY_PACKS
    assert {r for r, rule in RULES.items() if rule.pack in QUALITY_PACKS} == QUALITY_RULES
    assert len(QUALITY_RULES) == 50


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
    rule = next(r for r in RULES.values() if r.pack == "bugs")
    monkeypatch.setattr(selection, "_kind_of", lambda _pack: kind)
    assert selection.default(rule) == DENY


def test_a_rule_in_a_pack_this_build_does_not_carry_denies() -> None:
    stray = Rule(id="stray", pack="no-such-pack", title="t", suffixes=(".java",), scan=lambda _t: iter(()))
    assert default(stray) == DENY

"""The registry: every pack ships rules, every rule carries its evidence, the catalogue matches."""

from __future__ import annotations

import re

import pytest
from agentic_code_security.conftest import POLICY
from agentic_gate.catalogue import render
from agentic_gate.model import ALLOW, DENY
from agentic_gate.registry import _PACKS, packs, registry

RULES = registry()
KINDS = {"python", "js", "json", "yaml", "toml", "shell", "dockerfile", "env", "other"}
ASI = re.compile(r"^ASI(0[1-9]|10)$")
CWE = re.compile(r"^CWE-\d+$")
NOISY = {
    "bounds-unbounded-turns",
    "bounds-recursion-limit-high",
    "bounds-crewai-max-iter-high",
    "prompt-untrusted-in-system-message",
    "memory-mem0-unscoped",
    "supply-hf-unpinned-revision",
}
EXPECTED_PACKS = {
    "exec": "ASI05",
    "supply": "ASI04",
    "tools": "ASI02",
    "approval": "ASI09",
    "identity": "ASI03",
    "comms": "ASI07",
    "bounds": "ASI08",
    "prompt-memory": "ASI01",
    "code": "",
    "provenance": "",
}


def test_the_ten_packs_are_the_ones_the_policy_names() -> None:
    assert set(packs()) == set(EXPECTED_PACKS)


@pytest.mark.parametrize("pack_id", sorted(packs()))
def test_pack_ships_rules_and_says_what_it_covers(pack_id: str) -> None:
    pack = packs()[pack_id]
    assert any(r.pack == pack_id for r in RULES.values())
    assert pack.title
    assert pack.covers
    assert not EXPECTED_PACKS[pack_id] or EXPECTED_PACKS[pack_id] in pack.asi


def test_rule_ids_are_kebab_case_prefixed_by_their_pack_and_unique() -> None:
    assert len(RULES) == sum(len(module.RULES) for module in _PACKS)
    for rule in RULES.values():
        assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)+", rule.id)
        assert rule.pack in packs()
    for module in _PACKS:
        assert {r.pack for r in module.RULES} == {module.PACK.id}


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_carries_its_texts_and_its_evidence(rule_id: str) -> None:
    rule = RULES[rule_id]
    for field in ("title", "why", "fix", "refuses", "silent_on"):
        assert getattr(rule, field), f"{rule_id} has no {field}"
    assert set(rule.kinds) <= KINDS
    assert all(CWE.match(c) for c in rule.cwe)
    assert all(ASI.match(a) for a in rule.asi)
    assert rule.references
    assert all(ref.startswith("https://") for ref in rule.references)
    assert rule.default in {ALLOW, DENY}


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_a_rule_names_its_weakness_or_its_regime(rule_id: str) -> None:
    rule = RULES[rule_id]
    assert rule.cwe or rule.asi or rule.pack == "provenance"


def test_only_the_noisy_heuristics_start_as_allow() -> None:
    assert {r for r, rule in RULES.items() if rule.default == ALLOW} == NOISY


def test_the_agentic_security_packs_name_an_owasp_asi_entry() -> None:
    for rule in RULES.values():
        if rule.pack not in {"code", "provenance"}:
            assert rule.asi, rule.id


def test_the_catalogue_is_what_the_registry_renders() -> None:
    written = (POLICY / "references" / "rule-catalogue.md").read_text(encoding="utf-8")
    assert written == render(), "regenerate: python -c 'from agentic_gate.catalogue import render; ...'"


def test_the_catalogue_stays_inside_the_reference_budget() -> None:
    assert len(render().splitlines()) <= 300


def test_the_catalogue_names_every_rule_with_its_evidence() -> None:
    text = render()
    for rule in RULES.values():
        assert f"### {rule.id}" in text
        assert all(c in text for c in rule.cwe)

"""The agent scenarios are held to what they claim before anyone spends an agent session on them.

Each scenario's `evidence.bad` must trigger the rules it is about and `evidence.good` must trigger
nothing -- so a scenario cannot ask an agent to avoid a construct the engine would not refuse, or
grade a correct answer wrong. The fixture the agent starts from is silent under every rule, and
every rule the policy ships is the subject of at least one scenario.
"""

from __future__ import annotations

import kit
import pytest
from chock_security.decision import DENY, FileText
from chock_security.engine import evaluate
from chock_security.rules import packs, registry
from chock_security.selection import parse

RULES = registry()
ALL_DENY = dict.fromkeys(RULES, DENY)
SCENARIOS = kit.load_scenarios()
IDS = [s["id"] for s in SCENARIOS]
KINDS = {"direct", "bait", "control", "config", "waiver", "legacy"}
REQUIRED = {"id", "tier", "pack", "rules", "kind", "title", "prompt", "expect", "evidence"}


def _fired(path: str, text: str) -> set[str]:
    return {f.rule_id for f in evaluate([FileText(path, text)], ALL_DENY)}


def test_ids_are_unique() -> None:
    assert len(IDS) == len(set(IDS))


def test_the_fixture_is_silent_under_every_rule() -> None:
    files = [
        FileText(p.relative_to(kit.FIXTURE).as_posix(), p.read_text(encoding="utf-8"))
        for p in kit.FIXTURE.rglob("*")
        if p.is_file()
    ]
    assert [f.render() for f in evaluate(files, ALL_DENY)] == []


def test_every_rule_is_the_subject_of_a_scenario() -> None:
    covered = {rule for s in SCENARIOS for rule in s["rules"]}
    assert sorted(set(RULES) - covered) == []


@pytest.mark.parametrize("pack", sorted(packs()))
def test_every_pack_has_a_packs_tier_refusal_and_control(pack: str) -> None:
    kinds = {s["kind"] for s in SCENARIOS if s["pack"] == pack and kit.in_tier(s, "packs")}
    assert kinds & {"direct", "bait"}, f"{pack}: no direct or bait scenario in the packs tier"
    assert "control" in kinds, f"{pack}: no control scenario in the packs tier"


@pytest.mark.parametrize("item", SCENARIOS, ids=IDS)
def test_the_scenario_is_well_formed(item: dict) -> None:
    assert set(item) >= REQUIRED, sorted(REQUIRED - set(item))
    assert item["tier"] in kit.TIERS
    assert item["kind"] in KINDS
    assert item["expect"]["final"] in {"clean", "construct", "any"}
    assert item["expect"]["gate"] in {"refuse", "silent", "any"}
    assert item["rules"], "a scenario is about at least one rule"
    for rule_id in item["rules"]:
        assert rule_id in RULES, f"unknown rule {rule_id}"
        assert RULES[rule_id].pack == item["pack"], f"{rule_id} is in pack {RULES[rule_id].pack}"
    if item.get("selection") is not None:
        parse(kit.json.dumps(item["selection"]), RULES)


@pytest.mark.parametrize("item", SCENARIOS, ids=IDS)
def test_the_evidence_proves_the_scenario(item: dict) -> None:
    bad, good = item["evidence"]["bad"], item["evidence"]["good"]
    assert set(item["rules"]) & _fired(bad["path"], bad["text"]), "evidence.bad triggers none of the scenario's rules"
    assert _fired(good["path"], good["text"]) == set(), "evidence.good triggers a rule"


@pytest.mark.parametrize("item", SCENARIOS, ids=IDS)
def test_seeded_files_are_silent_unless_the_scenario_is_about_legacy_code(item: dict) -> None:
    fired = {rule for path, text in (item.get("files") or {}).items() for rule in _fired(path, text)}
    if item["kind"] == "legacy":
        assert fired & set(item["rules"]), "a legacy scenario seeds the breach it is about"
    else:
        assert fired == set()

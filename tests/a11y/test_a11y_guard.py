"""The no-a11y-regression guard, run through its two checkers one check at a time.

tools/check_a11y_rules.py proves the guard against every rule entry it ships and runs the commit
path in a throwaway repository; tools/check_a11y_table.py proves the decision table and the
parser behind it. CI still runs both as scripts. Here each of their checks is a named test, so a
failure names the check, and the guard's own code is measured for coverage like every other
shipped implementation.
"""

from __future__ import annotations

from collections.abc import Callable

import check_a11y_rules as rules
import check_a11y_table as table
import pytest

RULE_CHECKS = [
    rules.check_requirements,
    rules.check_provenance,
    rules.check_suppressions,
    rules.check_components,
    rules.check_void_elements,
    rules.check_noise,
    rules.check_a_name_the_path_also_spells,
    rules.check_name_length,
    rules.check_every_key_is_covered,
    rules.check_the_commit_path,
]
TABLE_CHECKS = [
    table.check_the_table_is_total,
    table.check_a_patch_at_scale,
    table.check_no_change_no_alarm,
    table.check_the_requirement_qualifiers,
    table.check_a_name_the_subtree_carries,
    table.check_what_the_parser_cannot_resolve,
    table.check_deleting_a_block_is_not_hiding_a_violation,
    table.check_hiding_a_subtree_retracts_the_names_inside_it,
    table.check_quality_is_judged_only_on_a_fix,
    table.check_components,
]


@pytest.fixture(scope="module")
def guard() -> object:
    return rules.load_guard()


@pytest.mark.parametrize("check", RULE_CHECKS, ids=[c.__name__ for c in RULE_CHECKS])
def test_the_guard_agrees_with_its_rules(guard: object, check: Callable) -> None:
    probe = rules.Probe(guard)
    check(probe)
    assert probe.checked, f"{check.__name__} checked nothing"
    assert probe.failures == []


@pytest.mark.parametrize("check", TABLE_CHECKS, ids=[c.__name__ for c in TABLE_CHECKS])
def test_the_decision_table_holds(guard: object, check: Callable) -> None:
    cases = table.Cases(guard)
    check(cases)
    assert cases.checked, f"{check.__name__} checked nothing"
    assert cases.failures == []


def test_both_checkers_run_every_check_they_define() -> None:
    for module, listed in ((rules, RULE_CHECKS), (table, TABLE_CHECKS)):
        defined = {name for name in dir(module) if name.startswith("check_")}
        assert defined == {c.__name__ for c in listed}, module.__name__

"""The infra review pairs' expectations on main: per policy, two lists that only shrink, and every case at its `expect`."""

from __future__ import annotations

import check_infra_pairs as pairs
import pytest

#: Catches the policy does not refuse. A fix flips `expect` to block or ask and drops the id here.
UNCAUGHT = {
    "block-wildcard-iam": frozenset(
        {
            "I01v",
            "I02",
            "I02v",
            "I04",
            "I04v",
            "I05",
            "I05v",
            "I06v",
            "I09",
            "I11v",
            "I12",
            "I12v",
        }
    ),
    "iam-policy-scan": frozenset(
        {
            "I07v",
            "I08",
            "I08v",
            "I09",
            "I12",
        }
    ),
    "protect-ci-workflows": frozenset(
        {
            "E05v",
            "E09",
            "E09v",
            "E10",
            "E10v",
            "K06v",
            "K07",
            "K07v",
            "K08",
            "K08v",
            "K09",
            "K09v",
        }
    ),
    "dockerfile-compose-security": frozenset(
        {
            "C06v",
        }
    ),
}

#: Correct work the policy blocks or asks about. A fix flips `expect` to allow and drops the id here.
REFUSED_CORRECT = {
    "block-wildcard-iam": frozenset(
        {
            "N05",
            "N06",
            "N07",
            "N08",
            "N12",
            "N18",
            "N22",
        }
    ),
    "iam-policy-scan": frozenset(
        {
            "N07",
            "N12",
        }
    ),
    "protect-ci-workflows": frozenset(
        {
            "Z04",
            "Z05",
            "Z06",
            "Z09",
            "Z12",
        }
    ),
    "dockerfile-compose-security": frozenset(
        {
            "S07",
            "S18",
            "S24",
            "S29",
        }
    ),
}

POLICIES = tuple(pairs.POLICIES)


@pytest.fixture(scope="module", params=POLICIES)
def measured(request: pytest.FixtureRequest) -> tuple[str, dict]:
    return request.param, pairs.measure(request.param)


def test_every_case_gives_the_verdict_it_expects(measured: tuple[str, dict]) -> None:
    policy, m = measured
    assert pairs.check(policy, m) == []


def test_every_case_expects_a_known_verdict(measured: tuple[str, dict]) -> None:
    _, m = measured
    assert {c["expect"] for c, *_ in m["seen"].values()} <= {"allow", "block", "ask", "warn"}


def test_the_uncaught_catches_only_shrink(measured: tuple[str, dict]) -> None:
    policy, m = measured
    now = set(m["missed"])
    assert now == UNCAUGHT[policy], (
        f"a catch stopped being refused: {sorted(now - UNCAUGHT[policy])}; "
        f"now refused, remove from UNCAUGHT: {sorted(UNCAUGHT[policy] - now)}"
    )


def test_the_refused_correct_work_only_shrinks(measured: tuple[str, dict]) -> None:
    policy, m = measured
    now = set(m["refused"])
    assert now == REFUSED_CORRECT[policy], (
        f"correct work is now refused: {sorted(now - REFUSED_CORRECT[policy])}; "
        f"no longer refused, remove from REFUSED_CORRECT: {sorted(REFUSED_CORRECT[policy] - now)}"
    )

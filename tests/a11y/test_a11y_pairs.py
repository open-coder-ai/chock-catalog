"""The review pairs' expectations: two lists that only shrink."""

from __future__ import annotations

import check_a11y_pairs as pairs

#: Regressions the guard does not block (R35 and R37 warn by ruling). A fix flips `expect` and drops the id here.
UNBLOCKED_REGRESSIONS = frozenset(
    {
        "R03",
        "R05",
        "R09",
        "R10",
        "R11",
        "R12",
        "R15",
        "R16",
        "R22",
        "R26",
        "R28",
        "R30",
        "R31",
        "R32",
        "R35",
        "R36",
        "R37",
        "R40",
        "R41",
        "R46",
        "R47",
        "R51",
    }
)
#: Correct work the guard blocks. A fix flips `expect` and drops the id here.
REFUSED_CORRECT = frozenset({"N04", "N05", "N06", "N11", "N12", "N32", "N33", "N52", "N54", "N55", "N56"})


def _ids(kinds: tuple[str, ...], unblocked: bool) -> set[str]:
    return {p["id"] for p in pairs.load_pairs() if p["kind"] in kinds and (p["expect"] != "block") == unblocked}


def test_every_pair_expects_a_known_verdict() -> None:
    assert {p["expect"] for p in pairs.load_pairs()} <= {"block", "warn", "silent"}


def test_the_unblocked_regressions_only_shrink() -> None:
    now = _ids(("regression", "swap_regression"), unblocked=True)
    assert now == UNBLOCKED_REGRESSIONS, (
        f"a regression stopped blocking: {sorted(now - UNBLOCKED_REGRESSIONS)}; "
        f"now blocked, remove from UNBLOCKED_REGRESSIONS: {sorted(UNBLOCKED_REGRESSIONS - now)}"
    )


def test_the_refused_correct_work_only_shrinks() -> None:
    now = _ids(("correct", "swap_correct"), unblocked=False)
    assert now == REFUSED_CORRECT, (
        f"correct work is now refused: {sorted(now - REFUSED_CORRECT)}; "
        f"no longer refused, remove from REFUSED_CORRECT: {sorted(REFUSED_CORRECT - now)}"
    )

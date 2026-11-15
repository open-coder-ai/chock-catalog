"""block-unsafe-code-execution against the 2026-11-15 review (REVIEW-deps.md, section 9): no catch lost, three refusals gone.

Every case runs through chock's own eval replay, the path `tests/policies/test_every_policy.py` uses.
"""

from __future__ import annotations

import pytest
from chock.eval.execute import run_case
from chock.eval.model import Case
from policies import gatekit
from policies.unsafe_exec_review_cases import CATCH
from policies.unsafe_exec_review_correct import CORRECT

POLICY = "block-unsafe-code-execution"

# The review's misses inside the claim (aliases, constructed names, other languages' shell calls): out of scope.
MISSED_BY_DESIGN = {"uce-c07", "uce-c08", "uce-c13", "uce-c23", "uce-c25", "uce-c27", "uce-c28"}
# Refused as correct work and still refused: a string literal or a docstring on one line (the gate judges one line
# and cannot tell a literal from code), Markdown (the gate cannot skip a file type), a vendored bundle and
# an old line the formatter rewrote or moved (the engine's baseline, E-1 and E-1b).
STILL_REFUSED = {"uce-k03", "uce-k05", "uce-k13", "uce-k19", "uce-k21", "uce-g02", "uce-g03", "uce-g04", "uce-g05"}
# Refused as correct work before this item and allowed after it.
NOW_ALLOWED = {"uce-k04", "uce-k06", "uce-k12", "uce-k16", "uce-k17", "uce-k18"}


def observed(case_id: str) -> str:
    """`block` or `allow`, as the replay judges the review's case."""
    event, files, head = {**CATCH, **CORRECT}[case_id]
    expect = "block" if case_id in CATCH else "allow"
    case = Case(
        id=case_id,
        category="review",
        prompt=case_id,
        expect=expect,
        policy_id=POLICY,
        execute={"event": event, "files": files, "head_files": head, "expect": expect},
    )
    result = run_case(case, gatekit.policy_dir(POLICY), gatekit.ROOT, [])
    assert result.outcome in ("pass", "fail"), result.detail
    return expect if result.outcome == "pass" else ("allow" if expect == "block" else "block")


CAUGHT = sorted(set(CATCH) - MISSED_BY_DESIGN)
SILENT = sorted(set(CORRECT) - STILL_REFUSED - NOW_ALLOWED)


def test_the_review_has_33_catches_and_34_rebuilt_correct_cases() -> None:
    assert len(CATCH) == 33
    assert len(CORRECT) == 34


@pytest.mark.parametrize("case_id", CAUGHT)
def test_every_catch_the_review_recorded_is_still_blocked(case_id: str) -> None:
    assert observed(case_id) == "block"


@pytest.mark.parametrize("case_id", sorted(NOW_ALLOWED))
def test_correct_work_the_item_names_is_allowed(case_id: str) -> None:
    assert observed(case_id) == "allow"


@pytest.mark.parametrize("case_id", SILENT)
def test_correct_work_that_passed_still_passes(case_id: str) -> None:
    assert observed(case_id) == "allow"

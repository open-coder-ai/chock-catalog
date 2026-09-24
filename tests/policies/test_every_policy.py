"""Every published policy, in every tree, proven by its own eval suite and by the framework's validator.

A policy nobody has adopted yet has had no user to find its bugs, so this is where they are
found. Three things hold for each one:

- the framework's own validator accepts it (schema, budgets, security baseline, effects);
- its suite is well-formed: every case has an id, a prompt and an expectation, ids are unique;
- every case with an executable form is replayed against the mechanism the policy ships -- the
  guard script for a command, the compiled gate for a change -- and must give the verdict it
  claims. Each case is its own named test, so a failure names the policy and the case.

A policy that ships a mechanism must prove it both ways: at least one case it refuses and one it
allows. java-security's script gate and the a11y guard have their own suites (tests/java_security,
tools/check_a11y_*), because chock's replay does not run a script gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from chock.eval.execute import run_case
from chock.eval.suites import Policy, load_cases
from chock.manifest import load_manifest
from chock.validation.engine import validate_artifact
from chock.validation.report import Report
from trees import ROOT, policy_dirs

POLICIES = policy_dirs()
#: Replayed by their own suites; chock's replay cannot drive a script gate or an event script.
OWN_SUITES = {"java-security", "no-a11y-regression"}


def _manifest(policy_dir: Path) -> dict:
    loaded = load_manifest(policy_dir)
    assert loaded is not None, f"{policy_dir.name} has no manifest"
    return loaded[0]


def _policy(policy_dir: Path) -> Policy:
    return Policy(policy_dir.name, policy_dir, _manifest(policy_dir))


def _executable() -> list[tuple[Path, object]]:
    rows = []
    for policy_dir in POLICIES:
        if policy_dir.name in OWN_SUITES:
            continue
        rows += [(policy_dir, case) for case in load_cases(policy_dir, policy_dir.name) if case.execute]
    return rows


EXECUTABLE = _executable()


def test_every_tree_is_populated() -> None:
    assert len(POLICIES) >= 40


@pytest.mark.parametrize("policy_dir", POLICIES, ids=[p.name for p in POLICIES])
def test_the_framework_validator_accepts_the_policy(policy_dir: Path) -> None:
    report = Report()
    validate_artifact(_manifest(policy_dir)["artifact"], policy_dir, "agnostic", report, ROOT, registry_check=False)
    assert [f"{f.check}: {f.message}" for f in report.errors] == []


@pytest.mark.parametrize("policy_dir", POLICIES, ids=[p.name for p in POLICIES])
def test_the_suite_is_well_formed(policy_dir: Path) -> None:
    cases = load_cases(policy_dir, policy_dir.name)
    assert cases, f"{policy_dir.name} ships no eval cases"
    ids = [c.id for c in cases]
    assert all(ids), f"{policy_dir.name} has a case without an id"
    assert len(ids) == len(set(ids)), f"{policy_dir.name} repeats a case id"
    for case in cases:
        assert case.prompt.strip(), f"{policy_dir.name}::{case.id} has no prompt"
        assert case.expect.strip(), f"{policy_dir.name}::{case.id} states no expectation"


@pytest.mark.parametrize(
    ("policy_dir", "case"),
    EXECUTABLE,
    ids=[f"{p.name}::{c.id}" for p, c in EXECUTABLE],
)
def test_the_case_gets_the_verdict_it_claims(policy_dir: Path, case) -> None:
    result = run_case(case, policy_dir, ROOT, _policy(policy_dir).guards)
    assert result.outcome == "pass", result.detail


MECHANISED = [p for p in POLICIES if p.name not in OWN_SUITES and (_policy(p).guards or _policy(p).gate)]


@pytest.mark.parametrize("policy_dir", MECHANISED, ids=[p.name for p in MECHANISED])
def test_a_shipped_mechanism_is_proven_both_ways(policy_dir: Path) -> None:
    expected = {str(c.execute.get("expect", "block")) for p, c in EXECUTABLE if p == policy_dir}
    assert {"block", "allow"} <= expected, f"{policy_dir.name} proves only {sorted(expected)}"

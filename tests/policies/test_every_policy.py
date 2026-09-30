"""Every published policy, in every tree, proven by its own eval suite and by the framework's validator.

A policy nobody has adopted yet has had no user to find its bugs, so this is where they are
found. Three things hold for each one:

- the framework's own validator accepts it (schema, budgets, security baseline, effects);
- its suite is well-formed: every case has an id, a prompt and an expectation, ids are unique;
- every case with an executable form is replayed against the mechanism the policy ships -- the
  guard script for a command, the compiled gate for a change -- and must give the verdict it
  claims. Each case is its own named test, so a failure names the policy and the case.

A policy that ships a mechanism must prove it both ways: at least one case it refuses (blocks, or
asks a person) and one it allows. A warn-only gate never refuses, so it proves the other pair: at
least one case warns, at least one is silent, and none blocks or asks. The a11y guard and the two tool_call
gates also have their own suites (tests/java_security, tools/check_a11y_*,
tests/policies/test_*_gate.py), because chock's replay does not drive those.
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
#: Replayed by their own suites; chock's replay cannot drive these tool_call gates.
OWN_SUITES = {"firecrawl-fallback-only", "token-efficiency"}


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


def _warns_only(policy_dir: Path) -> bool:
    return ((_manifest(policy_dir).get("hook") or {}).get("gate") or {}).get("action") == "warn"


@pytest.mark.parametrize("policy_dir", MECHANISED, ids=[p.name for p in MECHANISED])
def test_a_shipped_mechanism_is_proven_both_ways(policy_dir: Path) -> None:
    cases = [c for p, c in EXECUTABLE if p == policy_dir]
    expected = {str(c.execute.get("expect", "block")) for c in cases}
    if _warns_only(policy_dir):
        assert expected == {"warn", "allow"}, f"{policy_dir.name} only warns, yet proves {sorted(expected)}"
        return
    assert "allow" in expected, f"{policy_dir.name} proves no case it allows"
    assert expected & {"block", "ask"}, f"{policy_dir.name} proves no case it refuses: {sorted(expected)}"

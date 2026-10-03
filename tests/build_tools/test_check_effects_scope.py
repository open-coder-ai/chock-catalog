"""check_effects.py: --policies and --base narrow the run; concurrency never changes the report."""

from __future__ import annotations

from argparse import Namespace

import check_effects
import pytest

QUICK = "limit-diff-size,token-efficiency,firecrawl-fallback-only"


def test_no_scope_checks_every_policy() -> None:
    assert check_effects.scoped_ids(Namespace(policies=None, base=None)) is None


def test_policies_names_exactly_the_ids_given() -> None:
    assert check_effects.scoped_ids(Namespace(policies="git-safety,scan-secrets", base=None)) == {
        "git-safety",
        "scan-secrets",
    }


@pytest.mark.parametrize(("policies", "message"), [("no-such-policy", "unknown policy id"), (",", "at least one")])
def test_a_scope_that_names_nothing_real_is_an_error_not_an_empty_run(policies: str, message: str) -> None:
    with pytest.raises(SystemExit, match=message):
        check_effects.scoped_ids(Namespace(policies=policies, base=None))


def test_a_base_it_cannot_diff_against_checks_every_policy(capsys: pytest.CaptureFixture[str]) -> None:
    assert check_effects.scoped_ids(Namespace(policies=None, base="no-such-ref")) is None
    assert "checking every policy" in capsys.readouterr().err


def test_a_base_narrows_to_what_the_selector_covers(monkeypatch: pytest.MonkeyPatch) -> None:
    def selector(full: bool, covered: set[str]) -> object:
        return lambda *_: (full, covered, set())

    monkeypatch.setattr(check_effects, "changed_files", lambda *_: ["base/git-safety/manifest.yaml"])
    monkeypatch.setattr(check_effects, "select", selector(False, {"git-safety"}))
    assert check_effects.scoped_ids(Namespace(policies=None, base="origin/main")) == {"git-safety"}
    monkeypatch.setattr(check_effects, "select", selector(True, set()))
    assert check_effects.scoped_ids(Namespace(policies=None, base="origin/main")) is None


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str]:
    code = check_effects.main(list(args))
    return code, capsys.readouterr().out


def test_the_report_is_the_same_serial_or_concurrent_and_in_policy_order(capsys: pytest.CaptureFixture[str]) -> None:
    serial = run(capsys, "--policies", QUICK, "--jobs", "1")
    concurrent = run(capsys, "--policies", QUICK, "--jobs", "3")
    assert serial == concurrent
    assert serial[0] == 0
    assert "(firecrawl-fallback-only, limit-diff-size, token-efficiency)" in serial[1]

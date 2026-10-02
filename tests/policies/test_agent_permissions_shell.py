"""agent-permissions-scan: wrapped commands, inline interpreters and the auto-approve regex probes."""

from __future__ import annotations

import pytest
from policies.permskit import rules


@pytest.fixture(autouse=True)
def fresh_budget() -> None:
    rules.start_budget()


@pytest.mark.parametrize(
    "entry",
    [
        "Bash(env FOO=1 *)",
        "Bash(time curl:*)",
        "Bash(nohup curl *)",
        "Bash(command curl:*)",
        "Bash(sudo -n *)",
        "Bash(git -C . push *)",
        "Bash(git --no-pager push:*)",
        "Bash(git -c k=v push:*)",
        "Bash(find * -exec *)",
        "Bash(python -c *)",
        "Bash(node -e *)",
    ],
)
def test_wrappers_and_inline_interpreters_do_not_hide_a_wildcard(entry: str) -> None:
    assert rules.broad_entry(entry)


@pytest.mark.parametrize(
    "entry",
    ["Bash(sudo systemctl status:*)", "Bash(git -C x pull:*)", "Bash(python script.py *)", "Bash(env A=1 npm test:*)"],
)
def test_wrapped_scoped_commands_stay_scoped(entry: str) -> None:
    assert rules.broad_entry(entry) is None


@pytest.mark.parametrize("pattern", ["/^.{14,}/", "/^\\S+\\s+\\S+\\s+\\S+/"])
def test_long_probes_catch_patterns_that_only_match_long_commands(pattern: str) -> None:
    assert rules.approval_reach(pattern) == rules.RISKY_REASON


@pytest.mark.parametrize("pattern", ["/((((((((((.*)*)*)*)*)*)*)*)*)*)*z/", "/(?:(?:.?){30}){30}z/"])
def test_a_catastrophic_pattern_times_out_and_is_judged_broad(pattern: str) -> None:
    assert rules.approval_reach(pattern) == rules.ALL_REASON


def test_without_an_alarm_nested_quantifiers_are_broad_and_the_rest_is_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rules, "HAS_ALARM", False)
    assert rules.approval_reach("/(a+)+z/") == rules.ALL_REASON
    assert rules.approval_reach("/^git status$/") is None
    assert rules.approval_reach("/^curl/") == rules.RISKY_REASON


@pytest.mark.parametrize(
    "entry",
    [
        "Bash(timeout 5s:*)",
        "Bash(sudo -u root:*)",
        "Bash(env -u X:*)",
        "Bash(xargs -I {}:*)",
        "Bash(python3 -u -c:*)",
        "Bash(uv run python -c:*)",
        "Bash(uv run:*)",
        "Bash(git push:*)",
        "Bash(git push --force:*)",
    ],
)
def test_wrapper_option_values_and_runners_do_not_hide_a_wildcard(entry: str) -> None:
    assert rules.broad_entry(entry)


@pytest.mark.parametrize(
    "entry", ["Bash(git push origin main:*)", "Bash(uv run pytest:*)", "Bash(sudo -n systemctl status:*)"]
)
def test_these_stay_scoped(entry: str) -> None:
    assert rules.broad_entry(entry) is None


@pytest.mark.parametrize("pattern", ["/^rm -rf /", "/^curl -sSL /", "/^bash -c /", "/^curl .{40,}/", "/(?:sudo) /"])
def test_a_regex_that_needs_arguments_still_reaches_a_risky_command(pattern: str) -> None:
    assert rules.approval_reach(pattern) == rules.RISKY_REASON


def test_an_entry_too_long_to_judge_is_broad() -> None:
    assert rules.broad_entry("Bash(a b:" + "*" * 3000 + "x)") == "an entry too long to judge"


def test_once_the_probe_budget_is_spent_every_further_pattern_is_broad(monkeypatch: pytest.MonkeyPatch) -> None:
    assert rules.approval_reach("/^git status$/") is None
    monkeypatch.setattr(rules, "TOTAL_SECONDS", -1.0)
    assert rules.approval_reach("/^git status$/") == rules.ALL_REASON
    rules.start_budget()
    monkeypatch.setattr(rules, "TOTAL_SECONDS", 5.0)
    assert rules.approval_reach("/^git status$/") is None

"""agent-permissions-scan: wrapped commands, inline interpreters and the auto-approve regex probes."""

from __future__ import annotations

import pytest
from policies.permskit import rules


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

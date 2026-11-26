"""A prompt-submit policy is listed under its own README heading, not under the tool-call tier."""

from __future__ import annotations

import check_readme


def test_a_prompt_submit_policy_is_its_own_bucket() -> None:
    kinds, _ = check_readme.classify_readme()
    assert "scan-secrets-prompt" in kinds["prompt"]
    assert "scan-secrets-prompt" not in kinds["guard"]


def test_the_prompt_heading_lists_only_prompt_policies() -> None:
    kinds = {"gate": [], "guard": ["a"], "prompt": ["p"], "text": []}
    table = "\n**Enforced before the tool runs**\n\n| [`a`](x) | d | 1/1 |\n"
    wrong = check_readme.tier_table_problems(table + "\n**Refused when the prompt is submitted**\n\n| [`a`](x) | d | 1/1 |\n", kinds)
    assert any("p is a `prompt` policy but is not a row" in m for m in wrong)
    assert any("a is listed under 'Refused when the prompt is submitted'" in m for m in wrong)
    right = table.replace("\n**Enforced", "\n**Enforced at commit**\n\n\n**Enforced", 1)
    assert not check_readme.tier_table_problems(
        right + "\n**Refused when the prompt is submitted**\n\n| [`p`](x) | d | 1/1 |\n", kinds
    )

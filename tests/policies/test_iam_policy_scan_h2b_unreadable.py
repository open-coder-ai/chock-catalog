"""iam-policy-scan: refuse as unreadable only a plausible policy, and say why (review 2026-11-15, REVIEW-infra)."""

from __future__ import annotations

import pytest
from policies import iam_h2b_cases as cases
from policies.iamkit import gate

# Unreadable input: refused only when it is plausibly a policy, and the message says why.


def test_a_data_json_over_a_mebibyte_that_only_uses_the_words_is_allowed() -> None:
    text = cases.data_json()
    assert len(text) > 1 << 20
    assert gate.scan_file("data/records.json", text) == []


def test_an_edit_of_a_legacy_data_json_over_a_mebibyte_is_allowed() -> None:
    assert cases.added("data/records.json", cases.data_json(edited=3), cases.data_json()) == []


BIG_POLICY = {
    "allow-effect": '"Effect": "Allow"',
    "allow-escaped": '\\u0045ffect": "Allow"',
    "allow-in-a-string": '\\"Effect\\": \\"Allow\\"',
    "verbs": '"verbs": ["get"]',
    "binding": '"kind": "ClusterRoleBinding"',
    "role-assignment": '"type": "Microsoft.Authorization/roleAssignments"',
}


@pytest.mark.parametrize("case", sorted(BIG_POLICY))
def test_a_json_over_a_mebibyte_that_holds_a_grant_shape_is_still_refused(case: str) -> None:
    text = cases.data_json()[:-3] + f',\n{{"x": {BIG_POLICY[case]}}}\n]\n'
    if case == "allow-escaped":
        text = text.replace('{"x": \\u0045ffect": "Allow"}', '{"\\u0045ffect": "Allow"}')
    (finding,) = gate.scan_file("data/records.json", text)
    assert finding.rule == "iam-unreadable"


def test_a_yaml_over_a_mebibyte_is_still_refused() -> None:
    text = "effect: positive\nprincipal: x\n" + "#" + "x" * (1 << 20) + "\n"
    assert [f.rule for f in gate.scan_file("data.yaml", text)] == ["iam-unreadable"]


def test_a_go_templated_role_with_named_verbs_outside_templates_is_allowed() -> None:
    assert gate.scan_file("deploy/rbac.yaml", cases.GO_TEMPLATED_ROLE) == []


def test_a_go_templated_role_outside_templates_is_judged_not_skipped() -> None:
    text = cases.GO_TEMPLATED_ROLE.replace('"get", "list"', '"*"')
    assert [f.rule for f in gate.scan_file("deploy/rbac.yaml", text)] == ["k8s-rbac-wildcard"]


def test_a_json_with_nan_is_refused_and_the_message_names_the_reason() -> None:
    (finding,) = gate.scan_file("data/out.json", cases.NAN_JSON)
    assert finding.rule == "iam-unreadable"
    assert "NaN" in finding.render()


def test_an_oversize_policy_message_names_the_size() -> None:
    text = cases.data_json()[:-3] + ',\n{"Effect": "Allow"}\n]\n'
    (finding,) = gate.scan_file("data/records.json", text)
    assert "larger than" in finding.render()


def test_a_yaml_that_does_not_parse_says_so() -> None:
    (finding,) = gate.scan_file("role.yaml", "kind: Role\nrules:\n  - resources: ['*']\n    verbs: [a: b]\n")
    assert finding.rule == "iam-unreadable"
    assert "Refusing" not in finding.render()
    assert "line" in finding.render().lower()

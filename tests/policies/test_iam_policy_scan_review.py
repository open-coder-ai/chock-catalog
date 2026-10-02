"""iam-policy-scan: the bypasses the adversarial review found, each held shut."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from policies import iamkit
from policies.iamkit import ADMIN, doc, found, repo_with, rules, run_main

BLOCK, ASK = "block", "ask"
GRANT = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
ESCAPED = '{"Statement":{"\\u0045ffect":"Allow","Action":"*","Resource":"*"}}'
PAD = "# " + "x" * (1 << 20) + "\n"


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("p.json", ESCAPED),
        ("p.yaml", '"\\u0045ffect": Allow\n"Action": "*"\n"Resource": "*"\n'),
        ("m.tf", 'x = jsonencode({"\\u0045ffect"="Allow", Action="*", Resource="*"})\n'),
        ("r.json", '{"kin\\u0064": "ClusterRole", "rul\\u0065s": [{"v\\u0065rbs": ["*"]}]}'),
    ],
)
def test_a_key_spelled_with_escapes_is_still_read(name: str, text: str) -> None:
    assert rules(name, text)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("p.yaml", PAD + 'Statement:\n  Effect: !!str Allow\n  Action: "*"\n  Resource: "*"\n'),
        ("p.yaml", PAD + "Statement:\n  Effect: &a Allow\n  Action: '*'\n"),
        ("p.json", '{"pad": "' + "x" * (1 << 20) + '", "Effect": "Allow"}'),
        ("m.tf", PAD + 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["*"]\n  }\n}\n'),
        ("m.bicep", PAD + "resource a 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n}\n"),
    ],
)
def test_a_file_too_big_to_read_that_mentions_a_grant_is_refused_not_skipped(name: str, text: str) -> None:
    assert [f.rule for f in found({name: text})] == ["iam-unreadable"]


def test_a_big_file_that_mentions_no_grant_is_left_alone() -> None:
    assert rules("lock.json", '{"a": "' + "x" * (1 << 20) + '"}') == []


def test_a_policy_string_deep_inside_a_document_is_opened() -> None:
    inner = json.dumps({"Statement": [ADMIN]})
    deep = {"a": {"b": {"c": {"d": {"e": inner}}}}}
    assert rules("cfn.json", json.dumps(deep)) == [("iam-admin-grant", BLOCK)]
    cfn = "a:\n  b:\n    c:\n      d:\n        Content: '" + inner + "'\n"
    assert rules("cfn.yaml", cfn) == [("iam-admin-grant", BLOCK)]


def test_a_json_finding_is_placed_by_its_own_statement_not_by_the_ones_before_it() -> None:
    text = (
        '{"Statement":[\n'
        '{"Effect":"Allow","Action":"s3:GetObject","Resource":"a"},\n'
        '{"Effect":"Allow","Action":"*","Resource":"*"}\n]}\n'
    )
    assert [f.line for f in found({"p.json": text})] == [3]


def test_a_pragma_on_a_statement_that_is_not_the_grant_does_not_waive_it() -> None:
    text = (
        '{"Statement":[\n{"Effect":"Deny","Action":"*","Resource":"*"}, // pragma: allowlist broad-privilege\n'
        '{"Effect":"Allow","Action":"*","Resource":"*"}\n]}\n'
    )
    assert [f.rule for f in found({"j.json": text})] == ["iam-admin-grant"]
    waived = text.replace('"Resource":"*"}, // pragma: allowlist broad-privilege', '"Resource":"*"},').replace(
        '"Resource":"*"}\n]}', '"Resource":"*"} // pragma: allowlist broad-privilege\n]}'
    )
    assert found({"j.json": waived}) == []


TF = 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions   = ["*"] # pragma: allowlist broad-privilege\n    resources = ["*"]\n  }\n%s}\n'
NEW = '  statement {\n    actions   = ["iam:*"]\n    resources = ["*"]\n    principals {\n      type        = "*"\n      identifiers = ["*"]\n    }\n  }\n'


def test_in_the_agent_a_committed_pragma_waives_that_grant_and_no_other(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"m.tf": TF % ""})
    assert found({"m.tf": TF % ""}, "tool_use", repo) == []
    added = found({"m.tf": TF % NEW}, "tool_use", repo)
    assert sorted(f.rule for f in added) == ["iam-principal-wildcard", "iam-service-wildcard"]


def test_in_the_agent_a_pragma_does_not_excuse_a_twin_of_the_grant_it_was_given_for(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"m.tf": TF % ""})
    twin = TF % ('  statement {\n    actions   = ["*"]\n    resources = ["*"]\n  }\n')
    assert [f.rule for f in found({"m.tf": twin}, "tool_use", repo)] == ["iam-admin-grant"]


def test_in_the_agent_the_same_pragma_line_moved_onto_a_different_grant_does_not_waive_it(tmp_path: Path) -> None:
    yaml_head = "S:\n  - Effect: Allow\n    Action: '*'   # pragma: allowlist broad-privilege\n    Resource: '*'\n"
    repo = repo_with(tmp_path, {"p.yaml": yaml_head})
    other = (
        yaml_head
        + "T:\n  - Effect: Allow\n    Principal: x\n    Action: '*'   # pragma: allowlist broad-privilege\n    Resource: 'arn:aws:s3:::b'\n"
    )
    assert [f.rule for f in found({"p.yaml": other}, "tool_use", repo)] == ["iam-action-wildcard"]


@pytest.mark.parametrize(
    "scope",
    ['"${data.azurerm_subscription.primary.id}"', '"/providers/Microsoft.Management/managementGroups/root"', '"/"'],
)
def test_azure_owner_at_subscription_or_broader_scope_in_any_spelling(scope: str) -> None:
    tf = f'resource "azurerm_role_assignment" "a" {{\n  scope = {scope}\n  role_definition_name = "Owner"\n}}\n'
    assert rules("m.tf", tf) == [("azure-subscription-owner", BLOCK)]


@pytest.mark.parametrize("header", ["= [for p in ps: {", "= if (cond) {"])
def test_bicep_loops_and_conditions_are_read(header: str) -> None:
    owner = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    text = (
        f"targetScope = 'subscription'\nresource a 'Microsoft.Authorization/roleAssignments@2022-04-01' {header}\n"
        f"  properties: {{ roleDefinitionId: '{owner}' }}\n}}\n"
    )
    assert rules("m.bicep", text) == [("azure-subscription-owner", BLOCK)]


def test_bicep_with_many_unbalanced_resources_is_read_in_bounded_time() -> None:
    head = "resource a 'Microsoft.Authorization/roleAssignments@2022-04-01' = {\n"
    start = time.monotonic()
    rules("m.bicep", head * 3000)
    assert time.monotonic() - start < 5


def trust(condition: dict | None, action: str = "sts:AssumeRole") -> str:
    statement = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": action}
    if condition is not None:
        statement["Condition"] = condition
    return doc(statement)


@pytest.mark.parametrize(
    "condition",
    [
        {"StringLike": {"aws:PrincipalArn": "*"}},
        {"Null": {"aws:PrincipalArn": "true"}},
        {"StringNotEquals": {"aws:PrincipalOrgID": "o-x"}},
        {"StringEquals": {"aws:PrincipalOrgID": []}},
        {"Bool": {"aws:SecureTransport": "true"}},
        {"StringEquals": {}},
    ],
)
def test_a_wildcard_trust_condition_that_does_not_name_the_caller_is_refused(condition: dict) -> None:
    assert rules("t.json", trust(condition)) == [("iam-trust-wildcard", BLOCK)]


@pytest.mark.parametrize(
    "condition",
    [
        {"StringEquals": {"aws:PrincipalOrgID": "o-1"}},
        {"ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": ["o-1/*"]}},
        {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::1:role/*"}},
        {"StringEqualsIfExists": {"sts:ExternalId": "x"}},
    ],
)
def test_a_wildcard_trust_condition_that_names_the_caller_is_allowed(condition: dict) -> None:
    assert rules("t.json", trust(condition)) == []


def test_a_public_resource_policy_needs_a_condition_that_narrows_the_caller() -> None:
    weak = {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}
    strong = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
    assert rules("t.json", trust(weak, "s3:GetObject")) == [("iam-principal-wildcard", BLOCK)]
    assert rules("t.json", trust({"Bool": {"aws:SecureTransport": "true"}}, "s3:GetObject")) == [
        ("iam-principal-wildcard", BLOCK)
    ]
    assert rules("t.json", trust(strong, "s3:GetObject")) == []


def test_a_sidecar_with_a_repeated_key_is_not_understood(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = '{"version": 1, "waive": [], "waive": []}'
    code, _, err = run_main(monkeypatch, iamkit.payload({"p.json": doc(ADMIN), ".chock/iam-policy-scan.json": raw}))
    assert code == 1
    assert "twice" in err


def test_a_broken_sidecar_at_head_does_not_refuse_a_write_that_holds_no_grant(tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {".chock/iam-policy-scan.json": "{bad"})
    assert found({"notes.txt": "hello"}, "tool_use", repo) == []
    assert found({"p.json": doc({"Effect": "Allow", "Action": "s3:Get*", "Resource": "x"})}, "tool_use", repo) == []


def test_a_json_key_spelled_with_an_escape_is_still_a_finding_at_the_top_of_the_file() -> None:
    text = '{"Statement": {"Effect": "Allow", "\\u0041ction": "*", "Resource": "*"}}'
    assert [(f.rule, f.line) for f in found({"p.json": text})] == [("iam-admin-grant", 1)]

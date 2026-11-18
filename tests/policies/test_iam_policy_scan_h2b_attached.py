"""iam-policy-scan: AdministratorAccess attached through a managed-policy attribute (review 2026-11-15, REVIEW-infra)."""

from __future__ import annotations

import pytest
from policies import iam_h2b_cases as cases
from policies.iamkit import gate

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ATTACH = {
    "terraform-attachment": (
        "a.tf",
        f'resource "aws_iam_role_policy_attachment" "a" {{\n  policy_arn = "{ADMIN_ARN}"\n}}\n',
    ),
    "terraform-user": (
        "a.tf",
        f'resource "aws_iam_user_policy_attachment" "a" {{\n  user = "u"\n  policy_arn = "{ADMIN_ARN}"\n}}\n',
    ),
    "terraform-interpolated-partition": (
        "a.tf",
        'resource "aws_iam_role_policy_attachment" "a" {\n'
        '  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"\n}\n',
    ),
    "terraform-role-list": (
        "a.tf",
        f'resource "aws_iam_role" "r" {{\n  name = "r"\n  managed_policy_arns = ["{ADMIN_ARN}"]\n}}\n',
    ),
    "terraform-json": (
        "a.tf.json",
        f'{{"resource": {{"aws_iam_role_policy_attachment": {{"a": {{"policy_arn": "{ADMIN_ARN}"}}}}}}}}',
    ),
    "cloudformation-yaml": (
        "a.yaml",
        f"Resources:\n  R:\n    Type: AWS::IAM::Role\n    Properties:\n      ManagedPolicyArns:\n        - {ADMIN_ARN}\n",
    ),
    "cloudformation-sub": (
        "a.yaml",
        "Resources:\n  R:\n    Type: AWS::IAM::Role\n    Properties:\n      ManagedPolicyArns:\n"
        "        - !Sub arn:${AWS::Partition}:iam::aws:policy/AdministratorAccess\n",
    ),
    "cloudformation-json": (
        "a.json",
        f'{{"Resources": {{"R": {{"Type": "AWS::IAM::Role", "Properties": {{"ManagedPolicyArns": ["{ADMIN_ARN}"]}}}}}}}}',
    ),
    "other-partition": (
        "a.tf",
        'resource "aws_iam_role_policy_attachment" "a" {\n  policy_arn = "arn:aws-us-gov:iam::aws:policy/AdministratorAccess"\n}\n',
    ),
}


@pytest.mark.parametrize("case", sorted(ATTACH))
def test_administrator_access_attached_is_refused(case: str) -> None:
    path, text = ATTACH[case]
    assert cases.rule_of(path, text) == ("iam-admin-policy-attached", "block")


SAFE_ATTACH = {
    "read-only": (
        "a.tf",
        'resource "aws_iam_role_policy_attachment" "a" {\n  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"\n}\n',
    ),
    "named-in-a-description": (
        "a.tf",
        f'resource "aws_iam_role" "r" {{\n  description = "never attach {ADMIN_ARN}"\n}}\n',
    ),
    "a-comment": (
        "a.tf",
        '# arn:aws:iam::aws:policy/AdministratorAccess is forbidden\nresource "aws_iam_role" "r" {\n  name = "r"\n}\n',
    ),
    "prefix-of-another-policy": (
        "a.tf",
        'resource "aws_iam_role_policy_attachment" "a" {\n  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccessFoo"\n}\n',
    ),
    "a-customer-policy-of-that-name": (
        "a.tf",
        'resource "aws_iam_role_policy_attachment" "a" {\n  policy_arn = "arn:aws:iam::123456789012:policy/AdministratorAccess"\n}\n',
    ),
}


@pytest.mark.parametrize("case", sorted(SAFE_ATTACH))
def test_other_text_that_names_the_policy_is_not_an_attachment(case: str) -> None:
    path, text = SAFE_ATTACH[case]
    assert gate.scan_file(path, text) == []


def test_a_legacy_attachment_is_not_new_when_the_file_is_edited() -> None:
    old = ATTACH["terraform-attachment"][1]
    assert cases.added("a.tf", old + '\nresource "aws_iam_role" "x" {\n  name = "x"\n}\n', old) == []


def test_two_attachments_of_the_policy_to_different_roles_are_two_findings() -> None:
    text = "".join(
        f'resource "aws_iam_role_policy_attachment" "{n}" {{\n  role = "{n}"\n  policy_arn = "{ADMIN_ARN}"\n}}\n'
        for n in ("a", "b")
    )
    keys = {f.key for f in gate.scan_file("a.tf", text)}
    assert len(keys) == 2


def test_a_json_attachment_is_placed_on_the_line_of_its_key() -> None:
    text = (
        '{\n  "Resources": {\n    "R": {\n      "Properties": {\n        "ManagedPolicyArns": ["'
        + ADMIN_ARN
        + '"]\n      }\n    }\n  }\n}\n'
    )
    (finding,) = gate.scan_file("a.json", text)
    assert finding.line == 5


def test_a_yaml_attachment_is_placed_on_the_line_of_its_key() -> None:
    (finding,) = gate.scan_file(*ATTACH["cloudformation-yaml"])
    assert finding.line == 6


def test_a_terraform_attachment_is_placed_on_the_line_of_its_attribute() -> None:
    (finding,) = gate.scan_file(*ATTACH["terraform-user"])
    assert finding.line == 3

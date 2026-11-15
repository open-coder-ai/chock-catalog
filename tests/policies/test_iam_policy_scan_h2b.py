"""iam-policy-scan: the forms a line cannot judge, and the files that are not policies (review 2026-11-15, REVIEW-infra)."""

from __future__ import annotations

import pytest
from policies import iam_h2b_cases as cases
from policies.iamkit import gate

#: The counts the review's tables give for the gate before this change, and the ones this change is held to.
CAUGHT_BEFORE, CAUGHT_AFTER, CATCH_TOTAL = 12, 19, 24
BLOCKED_BEFORE, BLOCKED_AFTER, CORRECT_TOTAL = 2, 2, 26


def added(path: str, text: str, head: str | None = None) -> list:
    """The findings a change adds: those in the new text whose rule and id the old text does not already hold."""
    old = {f.key for f in gate.scan_file(path, head)} if head is not None else set()
    return [f for f in gate.scan_file(path, text) if f.key not in old]


@pytest.mark.parametrize("case", sorted(cases.CATCH))
def test_catch_table(case: str) -> None:
    path, text, expected = cases.CATCH[case]
    assert bool(added(path, text)) is expected


@pytest.mark.parametrize("case", sorted(cases.CORRECT))
def test_correct_work_table(case: str) -> None:
    path, text, head, blocked = cases.CORRECT[case]
    assert bool(added(path, text, head)) is blocked


def test_caught_n_of_24() -> None:
    caught = sum(bool(added(p, t)) for p, t, _ in cases.CATCH.values())
    print(f"caught {caught} of {len(cases.CATCH)}")  # noqa: T201
    assert (caught, len(cases.CATCH)) == (CAUGHT_AFTER, CATCH_TOTAL)


def test_correct_work_blocked_n_of_26() -> None:
    blocked = sum(bool(added(p, t, h)) for p, t, h, _ in cases.CORRECT.values())
    print(f"correct work blocked {blocked} of {len(cases.CORRECT)}")  # noqa: T201
    assert (blocked, len(cases.CORRECT)) == (BLOCKED_AFTER, CORRECT_TOTAL)


def rule_of(path: str, text: str) -> tuple[str, str]:
    (finding,) = gate.scan_file(path, text)
    return finding.rule, finding.tier


def test_the_tiers_chosen_for_the_new_forms() -> None:
    assert rule_of(*cases.CATCH["I02"][:2]) == ("iam-write-all-resources", "ask")
    assert rule_of(*cases.CATCH["I02v"][:2]) == ("iam-write-all-resources", "ask")
    assert rule_of(*cases.CATCH["I04"][:2]) == ("iam-passrole-all-resources", "block")
    assert rule_of(*cases.CATCH["I04v"][:2]) == ("iam-passrole-all-resources", "block")
    assert rule_of(*cases.CATCH["I10"][:2]) == ("iam-admin-policy-attached", "block")
    assert rule_of(*cases.CATCH["I10v"][:2]) == ("iam-admin-policy-attached", "block")
    assert rule_of(*cases.CATCH["I11v"][:2]) == ("iam-service-wildcard", "block")


def test_earlier_catches_keep_their_rule_and_tier() -> None:
    assert rule_of(*cases.CATCH["I01"][:2]) == ("iam-admin-grant", "block")
    assert rule_of(*cases.CATCH["I11"][:2]) == ("iam-service-wildcard", "block")
    assert rule_of(*cases.CATCH["I05"][:2]) == ("iam-allow-inverted", "block")
    assert rule_of(*cases.CATCH["I03"][:2]) == ("iam-principal-wildcard", "block")


WRITE_ON_ALL = [
    ("put", "s3:PutObject"),
    ("delete", "dynamodb:DeleteTable"),
    ("partial-write", "s3:Put*"),
    ("run", "ec2:RunInstances"),
    ("mixed", ["s3:GetObject", "s3:PutObject"]),
]


@pytest.mark.parametrize(("case", "action"), WRITE_ON_ALL, ids=[c for c, _ in WRITE_ON_ALL])
def test_a_write_action_on_every_resource_asks(case: str, action: object) -> None:
    assert rule_of("p.json", cases.policy(cases.allow(action))) == ("iam-write-all-resources", "ask")


READ_ON_ALL = [
    ("get", "s3:GetObject"),
    ("list", "s3:ListAllMyBuckets"),
    ("describe-wildcard", "ec2:Describe*"),
    ("sts", "sts:GetCallerIdentity"),
    ("logs", ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]),
    ("metrics", "cloudwatch:PutMetricData"),
    ("xray", ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]),
]


@pytest.mark.parametrize(("case", "action"), READ_ON_ALL, ids=[c for c, _ in READ_ON_ALL])
def test_a_read_or_logging_action_on_every_resource_is_silent(case: str, action: object) -> None:
    assert gate.scan_file("p.json", cases.policy(cases.allow(action))) == []


def test_a_write_on_a_named_resource_is_silent() -> None:
    assert gate.scan_file("p.json", cases.policy(cases.allow("s3:PutObject", "arn:aws:s3:::b/*"))) == []


def test_a_deny_of_a_write_on_every_resource_is_silent() -> None:
    assert gate.scan_file("p.json", cases.policy({**cases.allow("s3:PutObject"), "Effect": "Deny"})) == []


PASS_ROLE = {
    "service-condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}},
    "like-condition": {"StringLike": {"iam:PassedToService": "ecs*.amazonaws.com"}},
}


@pytest.mark.parametrize("case", sorted(PASS_ROLE))
def test_passrole_on_every_resource_with_a_passed_to_service_condition_is_silent(case: str) -> None:
    text = cases.policy(cases.allow("iam:PassRole", Condition=PASS_ROLE[case]))
    assert gate.scan_file("p.json", text) == []


@pytest.mark.parametrize(
    "action",
    ["iam:PassRole", "iam:Pass*", ["s3:GetObject", "iam:passrole"], "IAM:PASSROLE"],
)
def test_passrole_on_every_resource_blocks_however_it_is_spelled(action: object) -> None:
    assert rule_of("p.json", cases.policy(cases.allow(action))) == ("iam-passrole-all-resources", "block")


def test_passrole_on_a_named_role_is_silent() -> None:
    assert gate.scan_file("p.json", cases.policy(cases.allow("iam:PassRole", "arn:aws:iam::1:role/r"))) == []


def test_a_condition_that_names_everyone_does_not_excuse_passrole() -> None:
    text = cases.policy(cases.allow("iam:PassRole", Condition={"StringLike": {"iam:PassedToService": "*"}}))
    assert rule_of("p.json", text) == ("iam-passrole-all-resources", "block")


@pytest.mark.parametrize("service", ["lambda", "secretsmanager", "dynamodb", "organizations", "LAMBDA"])
def test_any_service_wildcard_on_every_resource_blocks(service: str) -> None:
    assert rule_of("p.json", cases.policy(cases.allow(f"{service}:*"))) == ("iam-service-wildcard", "block")


def test_an_unlisted_service_wildcard_on_a_named_resource_is_still_silent() -> None:
    assert gate.scan_file("p.json", cases.policy(cases.allow("lambda:*", "arn:aws:lambda:us-east-1:1:function:f"))) == []


def test_a_service_wildcard_on_a_named_resource_still_asks_for_the_listed_services() -> None:
    text = cases.policy(cases.allow("s3:*", "arn:aws:s3:::b"))
    assert rule_of("p.json", text) == ("iam-service-wildcard", "ask")


ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ATTACH = {
    "terraform-attachment": ("a.tf", f'resource "aws_iam_role_policy_attachment" "a" {{\n  policy_arn = "{ADMIN_ARN}"\n}}\n'),
    "terraform-user": ("a.tf", f'resource "aws_iam_user_policy_attachment" "a" {{\n  user = "u"\n  policy_arn = "{ADMIN_ARN}"\n}}\n'),
    "terraform-interpolated-partition": (
        "a.tf",
        'resource "aws_iam_role_policy_attachment" "a" {\n'
        '  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"\n}\n',
    ),
    "terraform-role-list": ("a.tf", f'resource "aws_iam_role" "r" {{\n  name = "r"\n  managed_policy_arns = ["{ADMIN_ARN}"]\n}}\n'),
    "terraform-json": ("a.tf.json", f'{{"resource": {{"aws_iam_role_policy_attachment": {{"a": {{"policy_arn": "{ADMIN_ARN}"}}}}}}}}'),
    "cloudformation-yaml": ("a.yaml", f"Resources:\n  R:\n    Type: AWS::IAM::Role\n    Properties:\n      ManagedPolicyArns:\n        - {ADMIN_ARN}\n"),
    "cloudformation-sub": (
        "a.yaml",
        "Resources:\n  R:\n    Type: AWS::IAM::Role\n    Properties:\n      ManagedPolicyArns:\n"
        "        - !Sub arn:${AWS::Partition}:iam::aws:policy/AdministratorAccess\n",
    ),
    "cloudformation-json": ("a.json", f'{{"Resources": {{"R": {{"Type": "AWS::IAM::Role", "Properties": {{"ManagedPolicyArns": ["{ADMIN_ARN}"]}}}}}}}}'),
    "other-partition": ("a.tf", 'resource "aws_iam_role_policy_attachment" "a" {\n  policy_arn = "arn:aws-us-gov:iam::aws:policy/AdministratorAccess"\n}\n'),
}


@pytest.mark.parametrize("case", sorted(ATTACH))
def test_administrator_access_attached_is_refused(case: str) -> None:
    path, text = ATTACH[case]
    assert rule_of(path, text) == ("iam-admin-policy-attached", "block")


SAFE_ATTACH = {
    "read-only": ("a.tf", 'resource "aws_iam_role_policy_attachment" "a" {\n  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"\n}\n'),
    "named-in-a-description": ("a.tf", f'resource "aws_iam_role" "r" {{\n  description = "never attach {ADMIN_ARN}"\n}}\n'),
    "a-comment": ("a.tf", f'# arn:aws:iam::aws:policy/AdministratorAccess is forbidden\nresource "aws_iam_role" "r" {{\n  name = "r"\n}}\n'),
    "prefix-of-another-policy": ("a.tf", 'resource "aws_iam_role_policy_attachment" "a" {\n  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccessFoo"\n}\n'),
    "a-customer-policy-of-that-name": ("a.tf", 'resource "aws_iam_role_policy_attachment" "a" {\n  policy_arn = "arn:aws:iam::123456789012:policy/AdministratorAccess"\n}\n'),
}


@pytest.mark.parametrize("case", sorted(SAFE_ATTACH))
def test_other_text_that_names_the_policy_is_not_an_attachment(case: str) -> None:
    path, text = SAFE_ATTACH[case]
    assert gate.scan_file(path, text) == []


def test_a_legacy_attachment_is_not_new_when_the_file_is_edited() -> None:
    old = ATTACH["terraform-attachment"][1]
    assert added("a.tf", old + '\nresource "aws_iam_role" "x" {\n  name = "x"\n}\n', old) == []


def test_two_attachments_of_the_policy_to_different_roles_are_two_findings() -> None:
    text = "".join(
        f'resource "aws_iam_role_policy_attachment" "{n}" {{\n  role = "{n}"\n  policy_arn = "{ADMIN_ARN}"\n}}\n'
        for n in ("a", "b")
    )
    keys = {f.key for f in gate.scan_file("a.tf", text)}
    assert len(keys) == 2


def test_a_json_attachment_is_placed_on_the_line_of_its_key() -> None:
    text = '{\n  "Resources": {\n    "R": {\n      "Properties": {\n        "ManagedPolicyArns": ["' + ADMIN_ARN + '"]\n      }\n    }\n  }\n}\n'
    (finding,) = gate.scan_file("a.json", text)
    assert finding.line == 5


def test_a_yaml_attachment_is_placed_on_the_line_of_its_key() -> None:
    (finding,) = gate.scan_file(*ATTACH["cloudformation-yaml"])
    assert finding.line == 6


def test_a_terraform_attachment_is_placed_on_the_line_of_its_attribute() -> None:
    (finding,) = gate.scan_file(*ATTACH["terraform-user"])
    assert finding.line == 3


# Unreadable input: refused only when it is plausibly a policy, and the message says why.


def test_a_data_json_over_a_mebibyte_that_only_uses_the_words_is_allowed() -> None:
    text = cases.data_json()
    assert len(text) > 1 << 20
    assert gate.scan_file("data/records.json", text) == []


def test_an_edit_of_a_legacy_data_json_over_a_mebibyte_is_allowed() -> None:
    assert added("data/records.json", cases.data_json(edited=3), cases.data_json()) == []


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

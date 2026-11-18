"""iam-policy-scan: the forms a line cannot judge, and the files that are not policies (review 2026-11-15, REVIEW-infra)."""

from __future__ import annotations

import json

import pytest
from policies import iam_h2b_cases as cases
from policies.iamkit import IMPL, gate

#: The counts the review's tables give for the gate before this change, and the ones this change is held to.
CAUGHT_BEFORE, CAUGHT_AFTER, CATCH_TOTAL = 12, 19, 24
BLOCKED_BEFORE, BLOCKED_AFTER, CORRECT_TOTAL = 2, 2, 26


@pytest.mark.parametrize("case", sorted(cases.CATCH))
def test_catch_table(case: str) -> None:
    path, text, expected = cases.CATCH[case]
    assert bool(cases.added(path, text)) is expected


@pytest.mark.parametrize("case", sorted(cases.CORRECT))
def test_correct_work_table(case: str) -> None:
    path, text, head, blocked = cases.CORRECT[case]
    assert bool(cases.added(path, text, head)) is blocked


def test_caught_n_of_24() -> None:
    caught = sum(bool(cases.added(p, t)) for p, t, _ in cases.CATCH.values())
    print(f"caught {caught} of {len(cases.CATCH)}")  # noqa: T201
    assert (caught, len(cases.CATCH)) == (CAUGHT_AFTER, CATCH_TOTAL)


def test_correct_work_blocked_n_of_26() -> None:
    blocked = sum(bool(cases.added(p, t, h)) for p, t, h, _ in cases.CORRECT.values())
    print(f"correct work blocked {blocked} of {len(cases.CORRECT)}")  # noqa: T201
    assert (blocked, len(cases.CORRECT)) == (BLOCKED_AFTER, CORRECT_TOTAL)


def test_the_tiers_chosen_for_the_new_forms() -> None:
    assert cases.rule_of(*cases.CATCH["I02"][:2]) == ("iam-write-all-resources", "ask")
    assert cases.rule_of(*cases.CATCH["I02v"][:2]) == ("iam-write-all-resources", "ask")
    assert cases.rule_of(*cases.CATCH["I04"][:2]) == ("iam-passrole-all-resources", "block")
    assert cases.rule_of(*cases.CATCH["I04v"][:2]) == ("iam-passrole-all-resources", "block")
    assert cases.rule_of(*cases.CATCH["I10"][:2]) == ("iam-admin-policy-attached", "block")
    assert cases.rule_of(*cases.CATCH["I10v"][:2]) == ("iam-admin-policy-attached", "block")
    assert cases.rule_of(*cases.CATCH["I11v"][:2]) == ("iam-service-wildcard", "block")


def test_earlier_catches_keep_their_rule_and_tier() -> None:
    assert cases.rule_of(*cases.CATCH["I01"][:2]) == ("iam-admin-grant", "block")
    assert cases.rule_of(*cases.CATCH["I11"][:2]) == ("iam-service-wildcard", "block")
    assert cases.rule_of(*cases.CATCH["I05"][:2]) == ("iam-allow-inverted", "block")
    assert cases.rule_of(*cases.CATCH["I03"][:2]) == ("iam-principal-wildcard", "block")


WRITE_ON_ALL = [
    ("put", "s3:PutObject"),
    ("delete", "dynamodb:DeleteTable"),
    ("partial-write", "s3:Put*"),
    ("run", "ec2:RunInstances"),
    ("mixed", ["s3:GetObject", "s3:PutObject"]),
]


@pytest.mark.parametrize("action", [a for _, a in WRITE_ON_ALL], ids=[c for c, _ in WRITE_ON_ALL])
def test_a_write_action_on_every_resource_asks(action: object) -> None:
    assert cases.rule_of("p.json", cases.policy(cases.allow(action))) == ("iam-write-all-resources", "ask")


READ_ON_ALL = [
    ("get", "s3:GetObject"),
    ("list", "s3:ListAllMyBuckets"),
    ("describe-wildcard", "ec2:Describe*"),
    ("sts", "sts:GetCallerIdentity"),
    ("logs", ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]),
    ("metrics", "cloudwatch:PutMetricData"),
    ("xray", ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]),
]


@pytest.mark.parametrize("action", [a for _, a in READ_ON_ALL], ids=[c for c, _ in READ_ON_ALL])
def test_a_read_or_logging_action_on_every_resource_is_silent(action: object) -> None:
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
    assert cases.rule_of("p.json", cases.policy(cases.allow(action))) == ("iam-passrole-all-resources", "block")


def test_passrole_on_a_named_role_is_silent() -> None:
    assert gate.scan_file("p.json", cases.policy(cases.allow("iam:PassRole", "arn:aws:iam::1:role/r"))) == []


def test_a_condition_that_names_everyone_does_not_excuse_passrole() -> None:
    text = cases.policy(cases.allow("iam:PassRole", Condition={"StringLike": {"iam:PassedToService": "*"}}))
    assert cases.rule_of("p.json", text) == ("iam-passrole-all-resources", "block")


@pytest.mark.parametrize("service", ["lambda", "secretsmanager", "dynamodb", "organizations", "LAMBDA"])
def test_any_service_wildcard_on_every_resource_blocks(service: str) -> None:
    assert cases.rule_of("p.json", cases.policy(cases.allow(f"{service}:*"))) == ("iam-service-wildcard", "block")


def test_an_unlisted_service_wildcard_on_a_named_resource_is_still_silent() -> None:
    assert (
        gate.scan_file("p.json", cases.policy(cases.allow("lambda:*", "arn:aws:lambda:us-east-1:1:function:f"))) == []
    )


def test_a_service_wildcard_on_a_named_resource_still_asks_for_the_listed_services() -> None:
    text = cases.policy(cases.allow("s3:*", "arn:aws:s3:::b"))
    assert cases.rule_of("p.json", text) == ("iam-service-wildcard", "ask")


VPC_ACCESS = [
    "ec2:CreateNetworkInterface",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DeleteNetworkInterface",
    "ec2:AssignPrivateIpAddresses",
    "ec2:UnassignPrivateIpAddresses",
]
SSM_AGENT = [
    "ssmmessages:CreateControlChannel",
    "ssmmessages:CreateDataChannel",
    "ssmmessages:OpenControlChannel",
    "ssmmessages:OpenDataChannel",
    "ec2messages:AcknowledgeMessage",
    "ec2messages:DeleteMessage",
    "ec2messages:FailMessage",
    "ec2messages:GetEndpoint",
    "ec2messages:GetMessages",
    "ec2messages:SendReply",
    "ssm:UpdateInstanceInformation",
]


@pytest.mark.parametrize("actions", [VPC_ACCESS, SSM_AGENT], ids=["vpc-access-lambda", "ssm-agent"])
def test_the_managed_policy_shapes_aws_ships_on_every_resource_are_silent(actions: list[str]) -> None:
    assert gate.scan_file("p.json", cases.policy(cases.allow(actions))) == []


def test_the_writes_that_are_legitimate_on_every_resource_live_in_a_dated_data_file() -> None:
    data = json.loads((IMPL / "iamscan" / "data" / "writes_on_all.json").read_text(encoding="utf-8"))
    assert data["as_of"] == "2026-11-15"
    assert data["note"]
    assert "logs:putlogevents" in data["actions"]
    assert all(a == a.lower() and ":" in a for a in data["actions"])


PASS_ROLE_RESOURCES = {
    "every-account": "arn:aws:iam::*:role/*",
    "one-account": "arn:aws:iam::123456789012:role/*",
    "other-partition": "arn:aws-us-gov:iam::*:role/*",
    "path-wildcards": "arn:aws:iam::123456789012:role/*/*",
}


@pytest.mark.parametrize("resource", sorted(PASS_ROLE_RESOURCES))
def test_passrole_on_every_role_blocks_like_a_star(resource: str) -> None:
    text = cases.policy(cases.allow("iam:PassRole", PASS_ROLE_RESOURCES[resource]))
    assert cases.rule_of("p.json", text) == ("iam-passrole-all-resources", "block")


def test_passrole_on_every_role_in_a_list_blocks() -> None:
    text = cases.policy(cases.allow("iam:PassRole", ["arn:aws:iam::1:role/a", "arn:aws:iam::*:role/*"]))
    assert cases.rule_of("p.json", text) == ("iam-passrole-all-resources", "block")


def test_passrole_on_every_role_with_a_passed_to_service_condition_is_silent() -> None:
    condition = {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
    text = cases.policy(cases.allow("iam:PassRole", "arn:aws:iam::*:role/*", Condition=condition))
    assert gate.scan_file("p.json", text) == []


@pytest.mark.parametrize(
    "resource",
    ["arn:aws:iam::123456789012:role/app-*", "arn:aws:iam::*:role/app", "arn:aws:iam::1:role/service-role/*"],
)
def test_passrole_on_a_narrower_role_pattern_is_silent(resource: str) -> None:
    assert gate.scan_file("p.json", cases.policy(cases.allow("iam:PassRole", resource))) == []

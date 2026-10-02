"""Final verification round: conditions that name every account, jsonencode wherever it sits, quadratic backtracking."""

from __future__ import annotations

import time

import pytest
from policies.iamkit import doc, rules

BLOCK, ASK = "block", "ask"
MAX_SECONDS = 10


def public(condition: dict, action: str = "s3:GetObject") -> str:
    return doc(
        {"Effect": "Allow", "Principal": "*", "Action": action, "Resource": "arn:aws:s3:::b/*", "Condition": condition}
    )


@pytest.mark.parametrize(
    "condition",
    [
        {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/*"}},
        {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}},
        {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::?:user/*"}},
        {"StringLike": {"aws:PrincipalArn": "*:role/*"}},
        {"StringLike": {"aws:PrincipalArn": "*iam*"}},
        {"ArnLike": {"aws:SourceArn": "arn:aws:sns:*:*:topic"}},
        {"ArnLike": {"aws:SourceArn": "arn:aws:sqs:us-east-1::q*"}},
        {"StringLike": {"aws:SourceAccount": "*123*"}},
        {"StringLike": {"aws:PrincipalAccount": "????????????"}},
        {"StringLike": {"kms:CallerAccount": "1*"}},
    ],
)
def test_a_condition_value_that_leaves_the_account_open_is_still_public(condition: dict) -> None:
    assert rules("p.json", public(condition)) == [("iam-principal-wildcard", BLOCK)]
    assert rules("t.json", public(condition, "sts:AssumeRole")) == [("iam-trust-wildcard", BLOCK)]


@pytest.mark.parametrize(
    "condition",
    [
        {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/*"}},
        {"StringLike": {"aws:PrincipalArn": "arn:*:iam::123456789012:user/dev-*"}},
        {"StringEquals": {"aws:PrincipalAccount": "123456789012"}},
        {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::uploads-bucket*"}},
        {"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:*"}},
        {"ArnLike": {"aws:SourceArn": "arn:aws:iam::${aws:PrincipalAccount}:role/*"}},
    ],
)
def test_a_condition_value_that_fixes_the_account_narrows_the_policy(condition: dict) -> None:
    assert rules("p.json", public(condition)) == []


def test_a_partial_assume_wildcard_to_another_account_asks() -> None:
    base = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}}
    assert rules("t.json", doc({**base, "Action": "sts:Assume*"})) == [("iam-trust-cross-account", ASK)]
    assert rules("t.json", doc({**base, "Action": "sts:GetCallerIdentity"})) == []


GRANT = '{Statement=[{Effect="Allow",Action="*",Resource="*"}]}'
SAFE = '{Statement=[{Effect="Allow",Action=["s3:GetObject"],Resource="arn:aws:s3:::b/*"}]}'


@pytest.mark.parametrize(
    "expr",
    [
        f'replace(jsonencode({GRANT}), "a", "b")',
        f'"${{jsonencode({GRANT})}}"',
        f"trimspace(jsonencode({GRANT}))",
        f"var.on ? jsonencode({GRANT}) : null",
        f"[jsonencode({GRANT})]",
        f"{{ admin = jsonencode({GRANT}) }}",
        f"merge({{ a = 1 }}, {{ policy = jsonencode({GRANT}) }})",
        f"[for x in var.l : jsonencode({GRANT})]",
    ],
)
def test_a_jsonencode_policy_is_read_wherever_it_sits_in_the_expression(expr: str) -> None:
    text = f"locals {{\n  p = {expr}\n}}\n"
    assert ("iam-admin-grant", BLOCK) in rules("m.tf", text)
    assert rules("m.tf", text.replace(GRANT, SAFE)) == []


def test_a_nested_jsonencode_is_judged_once() -> None:
    inner = 'jsonencode({Statement=[{Effect="Allow",Action="*",Resource="*"}]})'
    assert rules("m.tf", f"locals {{\n  p = jsonencode({{ a = {inner} }})\n}}\n") == [("iam-admin-grant", BLOCK)]


def test_a_paren_inside_a_jsonencode_string_does_not_end_the_call() -> None:
    text = 'locals {\n  p = jsonencode({Statement=[{Effect="Allow",Action="*",Resource="arn:aws:s3:::b/a)"}]})\n}\n'
    assert rules("m.tf", text) == [("iam-action-wildcard", ASK)]


def test_a_jsonencode_that_never_closes_is_not_a_crash() -> None:
    assert rules("m.tf", 'locals {\n  p = f(jsonencode({Effect = "x"}\n}\n') == [("iam-unreadable", BLOCK)]


def test_a_flood_of_jsonencode_text_is_refused_in_bounded_time() -> None:
    text = "locals {\n  p = [jsonencode(" + '"a)",' * 20000 + '"x")]\n}\n# Effect\n'
    start = time.monotonic()
    assert rules("m.tf", text) == [("iam-unreadable", BLOCK)]
    assert time.monotonic() - start < MAX_SECONDS


def test_a_quoted_json_policy_with_an_interpolation_is_read() -> None:
    quoted = '"{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"${var.r}\\"}]}"'
    assert rules("m.tf", f'resource "x" "y" {{\n  policy = {quoted}\n}}\n') == [("iam-action-wildcard", ASK)]
    safe = quoted.replace('\\"*\\"', '\\"s3:GetObject\\"')
    assert rules("m.tf", f'resource "x" "y" {{\n  policy = {safe}\n}}\n') == []


@pytest.mark.parametrize(
    "expr", ['"Action ${var.x} effect"', '"${var.env}-principal"', '"a \\" b ${c}"', '""', "var.x"]
)
def test_an_ordinary_template_string_is_not_a_policy(expr: str) -> None:
    assert rules("m.tf", f'resource "x" "y" {{\n  name = {expr}\n}}\n') == []


@pytest.mark.parametrize("filler", ["\\\\", '\\"', "\\u0041"])
def test_a_string_of_backslashes_is_not_quadratic(filler: str) -> None:
    text = '{"Effect":"Allow","x":"{' + filler * 150_000 + '"}'
    start = time.monotonic()
    rules("p.json", text)
    assert time.monotonic() - start < MAX_SECONDS


def test_a_json_string_that_is_not_a_policy_is_left_alone() -> None:
    text = '{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Note":"{not a policy}"}]}'
    assert rules("p.json", text) == []


def test_the_word_jsonencode_in_a_string_is_no_call() -> None:
    text = 'locals {\n  note = "see jsonencode( for the effect"\n}\n'
    assert rules("m.tf", text) == []


@pytest.mark.parametrize(
    "text",
    [
        'resource "x" "y" {\n  user_data = <<-EOT\n    # the principal investigator ${var.env}\n  EOT\n}\n',
        'resource "x" "y" {\n  sql = <<-EOT\n    select * from statement where effect = ${var.e}\n  EOT\n}\n',
        'resource "x" "y" {\n  config = jsonencode(var.statement)\n}\n',
        'resource "x" "y" {\n  config = jsonencode(merge(local.base, local.effect))\n}\n',
    ],
)
def test_a_computed_value_that_only_mentions_a_policy_word_is_not_refused(text: str) -> None:
    assert rules("m.tf", text) == []


@pytest.mark.parametrize(
    "text",
    [
        'resource "x" "y" {\n  p = <<-EOT\n    {"Statement":[{"Effect":"Allow",\n%{ if a }"Action":"*",%{ endif }"Resource":"*"}]}\n  EOT\n}\n',
        'resource "x" "y" {\n  p = jsonencode({ (var.k) = 1, Statement = [{ Effect = "Allow", Action = "*" }] })\n}\n',
        'resource "x" "y" {\n  p = jsonencode({ for k, v in var.m : k => v if v != "Effect" })\n}\n',
    ],
)
def test_a_computed_policy_object_is_refused_not_skipped(text: str) -> None:
    assert rules("m.tf", text) == [("iam-unreadable", BLOCK)]

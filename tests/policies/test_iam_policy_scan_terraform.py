"""iam-policy-scan: Terraform policy documents, jsonencode, heredocs, tf.json and Azure role assignments."""

from __future__ import annotations

import json

import pytest
from policies.iamkit import found, rules

BLOCK, ASK = "block", "ask"


def statement(body: str) -> str:
    return f'data "aws_iam_policy_document" "d" {{\n  statement {{\n{body}  }}\n}}\n'


HCL_CASES = {
    "doc-actions-multiline": (
        statement('    actions = [\n      "*"\n    ]\n    resources = ["*"]\n'),
        [("iam-admin-grant", BLOCK)],
    ),
    "doc-default-effect-is-allow": (
        statement('    actions   = ["*"]\n    resources = ["*"]\n'),
        [("iam-admin-grant", BLOCK)],
    ),
    "doc-computed-effect-is-allow": (
        statement('    effect    = var.effect\n    actions   = ["*"]\n    resources = ["*"]\n'),
        [("iam-admin-grant", BLOCK)],
    ),
    "doc-named-resource": (
        statement('    actions   = ["*"]\n    resources = ["arn:aws:s3:::b"]\n'),
        [("iam-action-wildcard", ASK)],
    ),
    "doc-computed-resource": (
        statement('    actions   = ["*"]\n    resources = var.resources\n'),
        [("iam-action-wildcard", ASK)],
    ),
    "doc-service": (statement('    actions   = ["s3:*"]\n    resources = ["*"]\n'), [("iam-service-wildcard", BLOCK)]),
    "doc-not-actions": (
        statement('    not_actions = ["iam:*"]\n    resources   = ["*"]\n'),
        [("iam-allow-inverted", BLOCK)],
    ),
    "doc-not-resources": (
        statement('    actions       = ["s3:GetObject"]\n    not_resources = ["arn:aws:s3:::b"]\n'),
        [("iam-allow-inverted", BLOCK)],
    ),
    "doc-principals-star": (
        statement(
            '    actions   = ["s3:GetObject"]\n    resources = ["arn:aws:s3:::b/*"]\n    principals {\n      type        = "*"\n      identifiers = ["*"]\n    }\n'
        ),
        [("iam-principal-wildcard", BLOCK)],
    ),
    "doc-principals-aws-star": (
        statement(
            '    actions   = ["s3:GetObject"]\n    principals {\n      type        = "AWS"\n      identifiers = ["*"]\n    }\n'
        ),
        [("iam-principal-wildcard", BLOCK)],
    ),
    "doc-principal-without-type": (
        statement('    actions = ["s3:GetObject"]\n    principals {\n      identifiers = ["*"]\n    }\n'),
        [("iam-principal-wildcard", BLOCK)],
    ),
    "doc-principals-without-identifiers": (
        statement('    actions = ["sts:AssumeRole"]\n    principals {\n      type = "AWS"\n    }\n'),
        [],
    ),
    "doc-not-principals": (
        statement(
            '    actions = ["s3:GetObject"]\n    not_principals {\n      type        = "AWS"\n      identifiers = ["arn:aws:iam::1:root"]\n    }\n'
        ),
        [("iam-allow-inverted", BLOCK)],
    ),
    "doc-trust-cross-account": (
        statement(
            '    actions = ["sts:AssumeRole"]\n    principals {\n      type        = "AWS"\n      identifiers = ["123456789012"]\n    }\n'
        ),
        [("iam-trust-cross-account", ASK)],
    ),
    "doc-trust-cross-account-external-id": (
        statement(
            '    actions = ["sts:AssumeRole"]\n    principals {\n      type        = "AWS"\n      identifiers = ["123456789012"]\n    }\n'
            '    condition {\n      test     = "StringEquals"\n      variable = "sts:ExternalId"\n      values   = ["x"]\n    }\n'
        ),
        [],
    ),
    "doc-principal-with-condition": (
        statement(
            '    actions = ["s3:GetObject"]\n    principals {\n      type        = "*"\n      identifiers = ["*"]\n    }\n'
            '    condition {\n      test     = "StringEquals"\n      variable = "aws:SourceVpce"\n      values   = ["v"]\n    }\n'
        ),
        [],
    ),
    "doc-condition-without-parts": (
        statement(
            '    actions = ["s3:GetObject"]\n    principals {\n      type        = "*"\n      identifiers = ["*"]\n    }\n    condition {\n    }\n'
        ),
        [("iam-principal-wildcard", BLOCK)],
    ),
    "doc-deny": (statement('    effect    = "Deny"\n    actions   = ["*"]\n    resources = ["*"]\n'), []),
    "doc-scoped": (statement('    actions   = ["s3:GetObject"]\n    resources = ["arn:aws:s3:::b/*"]\n'), []),
    "doc-dynamic-statement": (
        'data "aws_iam_policy_document" "d" {\n  dynamic "statement" {\n    for_each = var.s\n    content {\n      actions   = ["*"]\n      resources = ["*"]\n    }\n  }\n}\n',
        [("iam-admin-grant", BLOCK)],
    ),
    "doc-other-block-ignored": (
        '# statement\ndata "aws_iam_policy_document" "d" {\n  override_policy_documents = [data.x.y.json]\n  version = "2012-10-17"\n  other {\n    actions = ["*"]\n  }\n}\n',
        [],
    ),
    "jsonencode-multiline": (
        'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{\n      Effect   = "Allow"\n      Action   = "*"\n'
        '      Resource = "*"\n    }]\n  })\n}\n',
        [("iam-admin-grant", BLOCK)],
    ),
    "jsonencode-with-references": (
        'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n    Statement = [{\n      Effect   = "Allow"\n      Action   = "*"\n      Resource = aws_s3_bucket.b.arn\n    }]\n  })\n}\n',
        [("iam-action-wildcard", ASK)],
    ),
    "jsonencode-scoped": (
        'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n    Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "*" }]\n  })\n}\n',
        [],
    ),
    "jsonencode-of-a-reference": ('resource "aws_iam_policy" "p" {\n  policy = jsonencode(local.policy)\n}\n', []),
    "jsonencode-computed-key": (
        'resource "aws_iam_policy" "p" {\n  policy = jsonencode({\n    (var.k) = 1\n    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]\n  })\n}\n',
        [("iam-unreadable", BLOCK)],
    ),
    "jsonencode-computed-key-no-grant-words": (
        'resource "x" "p" {\n  policy = jsonencode({\n    (var.k) = 1\n  })\n}\n',
        [],
    ),
    "heredoc": (
        'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\nEOF\n}\n',
        [("iam-admin-grant", BLOCK)],
    ),
    "heredoc-indented": (
        'resource "aws_iam_policy" "p" {\n  policy = <<-POLICY\n    {"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\n  POLICY\n}\n',
        [("iam-admin-grant", BLOCK)],
    ),
    "heredoc-interpolated": (
        'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{"Statement":[{"Effect":"Allow","Action":"*","Resource":"${aws_s3_bucket.b.arn}"}]}\nEOF\n}\n',
        [("iam-action-wildcard", ASK)],
    ),
    "heredoc-interpolation-outside-a-string": (
        'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{"Statement":[{"Effect":"Allow","Action":"*","Resource":${jsonencode(var.r)}}]}\nEOF\n}\n',
        [("iam-action-wildcard", ASK)],
    ),
    "heredoc-interpolated-scoped": (
        'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{"Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"${x}"}]}\nEOF\n}\n',
        [],
    ),
    "heredoc-interpolated-cut": (
        'resource "aws_iam_policy" "p" {\n  policy = <<EOF\n{"Statement":[{"Effect":"Allow","Action":"*", ${x}\nEOF\n}\n',
        [("iam-unreadable", BLOCK)],
    ),
    "heredoc-interpolated-cut-no-grant-words": (
        '# statement\nresource "x" "p" {\n  note = <<EOF\n{"a": ${x},\nEOF\n}\n',
        [],
    ),
    "heredoc-not-json": ('resource "x" "p" {\n  note = <<EOF\nhello ${x}\nEOF\n}\n', []),
    "tfvars-object": (
        'policy = {\n  Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]\n}\n',
        [("iam-admin-grant", BLOCK)],
    ),
    "locals-object": (
        'locals {\n  p = { Effect = "Allow", Action = ["*"], Resource = "*" }\n}\n',
        [("iam-admin-grant", BLOCK)],
    ),
}


@pytest.mark.parametrize("case", sorted(HCL_CASES))
def test_terraform_grant_is_judged_as_written(case: str) -> None:
    text, expected = HCL_CASES[case]
    assert rules("main.tf", text) == expected


def test_a_terraform_finding_is_reported_at_the_attribute_it_is_about() -> None:
    text = statement('    actions = [\n      "*"\n    ]\n    resources = ["*"]\n')
    assert [f.line for f in found({"main.tf": text})] == [3]


def test_tfvars_and_hcl_files_are_read_too() -> None:
    text = 'p = { Effect = "Allow", Action = "*", Resource = "*" }\n'
    assert rules("prod.auto.tfvars", text) == [("iam-admin-grant", BLOCK)]
    assert rules("stack.hcl", text) == [("iam-admin-grant", BLOCK)]


def test_a_terraform_file_that_names_a_grant_and_cannot_be_read_is_refused() -> None:
    assert rules("main.tf", 'resource "x" "y" {\n  Effect = "Allow\n') == [("iam-unreadable", BLOCK)]


def test_a_terraform_file_that_cannot_be_read_and_names_no_grant_is_not_judged() -> None:
    assert rules("main.tf", 'resource "x" "y" {\n  # statement\n  foo = \n') == []


TFJSON = {
    "resource": {
        "aws_iam_policy": {
            "p": {"policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})}
        }
    },
}


def test_tf_json_with_a_policy_string_is_read() -> None:
    assert rules("main.tf.json", json.dumps(TFJSON)) == [("iam-admin-grant", BLOCK)]


def test_tf_json_with_an_object_policy_and_a_policy_document_is_read() -> None:
    doc = {
        "data": {"aws_iam_policy_document": {"d": {"statement": [{"actions": ["*"], "resources": ["*"]}]}}},
        "resource": {
            "aws_iam_policy": {"p": {"policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}}
        },
    }
    assert [r for r, _ in rules("main.tf.json", json.dumps(doc))] == ["iam-admin-grant", "iam-admin-grant"]


def test_tf_json_a_schema_cannot_read_falls_back_to_plain_json() -> None:
    odd = {"unknownblock": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}
    assert rules("main.tf.json", json.dumps(odd)) == [("iam-admin-grant", BLOCK)]
    assert rules(
        "prod.tfvars.json", json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    ) == [("iam-admin-grant", BLOCK)]

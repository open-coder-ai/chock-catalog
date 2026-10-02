"""iam-policy-scan: AWS statements in JSON, YAML and Terraform, whatever the line layout, key case or nesting."""

from __future__ import annotations

import json

import pytest
from policies.iamkit import ADMIN, doc, found, rules

BLOCK, ASK = "block", "ask"


def stmt(**keys: object) -> dict:
    return {"Effect": "Allow", **keys}


JSON_CASES = {
    "list-action-star-all": (doc(ADMIN), [("iam-admin-grant", BLOCK)]),
    "string-action-star-all": (doc(stmt(Action="*", Resource="*")), [("iam-admin-grant", BLOCK)]),
    "star-colon-star": (doc(stmt(Action="*:*", Resource="*")), [("iam-admin-grant", BLOCK)]),
    "star-with-spaces": (doc(stmt(Action=[" * "], Resource=["*"])), [("iam-admin-grant", BLOCK)]),
    "star-among-others": (doc(stmt(Action=["s3:Get*", "*"], Resource="*")), [("iam-admin-grant", BLOCK)]),
    "star-named-resource": (doc(stmt(Action="*", Resource="arn:aws:s3:::b")), [("iam-action-wildcard", ASK)]),
    "star-no-resource": (doc(stmt(Action="*")), [("iam-action-wildcard", ASK)]),
    "unicode-escaped-star": (
        '{"Statement":[{"Effect":"Allow","Action":"\\u002a","Resource":"*"}]}',
        [("iam-admin-grant", BLOCK)],
    ),
    "single-statement-object": (json.dumps({"Statement": ADMIN}), [("iam-admin-grant", BLOCK)]),
    "bare-statement": (json.dumps(ADMIN), [("iam-admin-grant", BLOCK)]),
    "key-case-variants": (
        json.dumps({"statement": [{"EFFECT": "allow", "ACTION": "*", "resource": "*"}]}),
        [("iam-admin-grant", BLOCK)],
    ),
    "effect-case": (doc({"Effect": "ALLOW", "Action": "*", "Resource": "*"}), [("iam-admin-grant", BLOCK)]),
    "effect-not-a-string": (doc({"Effect": ["Allow"], "Action": "*", "Resource": "*"}), [("iam-admin-grant", BLOCK)]),
    "service-all": (doc(stmt(Action="s3:*", Resource="*")), [("iam-service-wildcard", BLOCK)]),
    "service-case": (doc(stmt(Action=["IAM:*"], Resource=["*"])), [("iam-service-wildcard", BLOCK)]),
    "service-named": (
        doc(stmt(Action="kms:*", Resource="arn:aws:kms:us-east-1:1:key/k")),
        [("iam-service-wildcard", ASK)],
    ),
    "ec2-and-sts": (doc(stmt(Action=["ec2:*", "sts:*"], Resource="*")), [("iam-service-wildcard", BLOCK)]),
    "not-action": (doc(stmt(NotAction="iam:*", Resource="*")), [("iam-allow-inverted", BLOCK)]),
    "not-action-star": (doc(stmt(NotAction="*", Resource="*")), [("iam-allow-inverted", BLOCK)]),
    "not-resource": (doc(stmt(Action="s3:GetObject", NotResource="arn:aws:s3:::b")), [("iam-allow-inverted", BLOCK)]),
    "not-principal": (
        doc(stmt(NotPrincipal={"AWS": "x"}, Action="s3:Get*", Resource="*")),
        [("iam-allow-inverted", BLOCK)],
    ),
    "not-action-key-case": (doc(stmt(notaction="iam:*", Resource="*")), [("iam-allow-inverted", BLOCK)]),
    "principal-star-string": (
        doc(stmt(Principal="*", Action="s3:GetObject", Resource="arn:aws:s3:::b/*")),
        [("iam-principal-wildcard", BLOCK)],
    ),
    "principal-aws-star": (
        doc(stmt(Principal={"AWS": "*"}, Action="s3:GetObject", Resource="arn:aws:s3:::b/*")),
        [("iam-principal-wildcard", BLOCK)],
    ),
    "principal-aws-list": (
        doc(stmt(Principal={"AWS": ["arn:aws:iam::1:root", "*"]}, Action="s3:Get*", Resource="*")),
        [("iam-principal-wildcard", BLOCK)],
    ),
    "principal-list": (doc(stmt(Principal=["*"], Action="s3:Get*", Resource="*")), [("iam-principal-wildcard", BLOCK)]),
    "principal-empty-condition": (
        doc(stmt(Principal="*", Action="s3:Get*", Resource="*", Condition={})),
        [("iam-principal-wildcard", BLOCK)],
    ),
    "trust-star-no-condition": (
        doc(stmt(Principal={"AWS": "*"}, Action="sts:AssumeRole")),
        [("iam-trust-wildcard", BLOCK)],
    ),
    "trust-star-weak-condition": (
        doc(stmt(Principal={"AWS": "*"}, Action="sts:AssumeRole", Condition={"Bool": {"aws:SecureTransport": "true"}})),
        [("iam-trust-wildcard", BLOCK)],
    ),
    "trust-star-assume-web": (
        doc(stmt(Principal="*", Action="sts:AssumeRoleWithSAML")),
        [("iam-trust-wildcard", BLOCK)],
    ),
    "cross-account": (
        doc(stmt(Principal={"AWS": "arn:aws:iam::123456789012:root"}, Action="sts:AssumeRole")),
        [("iam-trust-cross-account", ASK)],
    ),
    "cross-account-bare-id": (
        doc(stmt(Principal={"AWS": ["123456789012"]}, Action=["sts:AssumeRole"])),
        [("iam-trust-cross-account", ASK)],
    ),
    "cross-account-other-partition": (
        doc(stmt(Principal={"AWS": "arn:aws-cn:iam::123456789012:role/r"}, Action="sts:*")),
        [("iam-service-wildcard", ASK), ("iam-trust-cross-account", ASK)],
    ),
    "cross-account-weak-condition": (
        doc(
            stmt(
                Principal={"AWS": "arn:aws:iam::123456789012:root"},
                Action="sts:AssumeRole",
                Condition={"Bool": {"aws:SecureTransport": "true"}},
            )
        ),
        [("iam-trust-cross-account", ASK)],
    ),
    "admin-and-public": (
        doc(stmt(Principal="*", Action="*", Resource="*")),
        [("iam-admin-grant", BLOCK), ("iam-trust-wildcard", BLOCK)],
    ),
}

JSON_ALLOWED = {
    "scoped-list": doc(stmt(Action=["s3:GetObject", "s3:PutObject"], Resource="arn:aws:s3:::b/*")),
    "partial-wildcard": doc(stmt(Action="s3:Get*", Resource="arn:aws:s3:::b/*")),
    "unlisted-service-wildcard": doc(stmt(Action="logs:*", Resource="*")),
    "deny-star": doc({"Effect": "Deny", "Action": "*", "Resource": "*"}),
    "deny-not-action": doc({"Effect": "Deny", "NotAction": ["iam:ChangePassword"], "Resource": "*"}),
    "deny-case": doc({"EFFECT": " deny ", "Action": "*", "Resource": "*"}),
    "deny-principal-star": doc({"Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*"}),
    "no-effect": json.dumps({"Action": "*", "Resource": "*"}),
    "principal-with-condition": doc(
        stmt(Principal="*", Action="s3:GetObject", Resource="b", Condition={"StringEquals": {"aws:SourceVpce": "v"}})
    ),
    "trust-star-names-org": doc(
        stmt(Principal={"AWS": "*"}, Action="sts:AssumeRole", Condition={"StringEquals": {"aws:PrincipalOrgID": "o-1"}})
    ),
    "trust-named-role": doc(stmt(Principal={"AWS": "arn:aws:iam::${AWS::AccountId}:root"}, Action="sts:AssumeRole")),
    "cross-account-external-id": doc(
        stmt(
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Action="sts:AssumeRole",
            Condition={"StringEquals": {"sts:ExternalId": "x"}},
        )
    ),
    "cross-account-mfa": doc(
        stmt(
            Principal={"AWS": "arn:aws:iam::123456789012:root"},
            Action="sts:AssumeRole",
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
    ),
    "principal-string-that-is-not-a-wildcard": doc(
        stmt(Principal="arn:aws:iam::123456789012:root", Action="sts:AssumeRole")
    ),
    "service-principal": doc(stmt(Principal={"Service": "lambda.amazonaws.com"}, Action="sts:AssumeRole")),
    "cross-account-not-assume": doc(
        stmt(Principal={"AWS": "arn:aws:iam::123456789012:root"}, Action="s3:GetObject", Resource="b")
    ),
    "principal-aws-computed-shape": doc(stmt(Principal={"AWS": 5}, Action="sts:AssumeRole")),
    "not-json-policy": json.dumps({"name": "x", "statement": "text"}),
    "empty-statement-list": doc(),
}


@pytest.mark.parametrize("case", sorted(JSON_CASES))
def test_json_grant_is_judged_as_the_document_says(case: str) -> None:
    text, expected = JSON_CASES[case]
    assert rules("p.json", text) == expected


@pytest.mark.parametrize("case", sorted(JSON_ALLOWED))
def test_json_that_is_not_a_broad_grant_is_allowed(case: str) -> None:
    assert rules("p.json", JSON_ALLOWED[case]) == []


def test_a_json_finding_is_reported_at_the_key_it_is_about() -> None:
    text = '{\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": [\n        "*"\n      ],\n      "Resource": "*"\n    }\n  ]\n}\n'
    assert [f.line for f in found({"p.json": text})] == [5]


def test_two_findings_of_one_kind_are_placed_one_after_the_other() -> None:
    text = '{"Statement": [\n{"Effect": "Allow", "Action": "*", "Resource": "*"},\n{"Effect": "Allow", "Action": "*", "Resource": "*"}]}\n'
    assert [f.line for f in found({"p.json": text})] == [2, 3]


def test_the_id_is_the_statement_not_its_place_or_sid() -> None:
    first = found({"a.json": doc(ADMIN, {"Effect": "Allow", "Action": "s3:Get*", "Resource": "x"})})
    moved = found(
        {"a.json": doc({"Effect": "Allow", "Action": "s3:Get*", "Resource": "x"}, {**ADMIN, "Sid": "renamed"})}
    )
    assert [f.key for f in first] == [f.key for f in moved]
    other = found({"a.json": doc({**ADMIN, "Condition": {"Bool": {"a": "b"}}})})
    assert other[0].key != first[0].key


def test_json_inside_a_json_string_is_read() -> None:
    inner = json.dumps({"Statement": [ADMIN]})
    assert rules("plan.json", json.dumps({"policy": inner})) == [("iam-admin-grant", BLOCK)]


def test_json_inside_a_string_inside_a_string_is_read_to_a_fixed_depth() -> None:
    inner = json.dumps({"Statement": [ADMIN]})
    deep = json.dumps({"a": json.dumps({"b": json.dumps({"c": json.dumps({"d": inner})})})})
    assert rules("plan.json", deep) == []


def test_a_json_string_that_looks_like_a_policy_but_is_cut_is_refused() -> None:
    assert rules("plan.json", json.dumps({"policy": '{"Statement": [{"Effect": "Allow",'})) == [
        ("iam-unreadable", BLOCK)
    ]


YAML_CASES = {
    "double-quoted-list": (
        'Statement:\n  - Effect: Allow\n    Action:\n      - "*"\n    Resource: "*"\n',
        [("iam-admin-grant", BLOCK)],
    ),
    "single-quoted": (
        "Statement:\n  - Effect: Allow\n    Action: '*'\n    Resource: '*'\n",
        [("iam-admin-grant", BLOCK)],
    ),
    "flow-style": ("Statement: [{Effect: Allow, Action: ['*'], Resource: ['*']}]\n", [("iam-admin-grant", BLOCK)]),
    "cloudformation": (
        "Resources:\n  R:\n    Type: AWS::IAM::Role\n    Properties:\n      Policies:\n        - PolicyName: p\n          PolicyDocument:\n"
        "            Statement:\n              - Effect: Allow\n                NotAction: iam:*\n                Resource: '*'\n",
        [("iam-allow-inverted", BLOCK)],
    ),
    "tagged-sub-keeps-text": (
        "Statement:\n  - Effect: Allow\n    Action: !Sub '*'\n    Resource: '*'\n",
        [("iam-admin-grant", BLOCK)],
    ),
    "anchor-and-alias": (
        "c: &a\n  Effect: Allow\n  Action: '*'\n  Resource: '*'\nStatement:\n  - *a\n",
        [("iam-admin-grant", BLOCK), ("iam-admin-grant", BLOCK)],
    ),
    "merge-key": (
        "b: &b\n  Effect: Allow\n  Action: ['*']\nStatement:\n  - <<: *b\n    Resource: '*'\n",
        [("iam-action-wildcard", ASK), ("iam-admin-grant", BLOCK)],
    ),
    "merge-key-list": (
        "a: &a\n  Effect: Allow\nb: &b\n  Action: '*'\nStatement:\n  - <<: [*a, *b]\n    Resource: '*'\n",
        [("iam-admin-grant", BLOCK)],
    ),
    "merge-explicit-wins": (
        "b: &b\n  Action: 's3:Get*'\nStatement:\n  - <<: *b\n    Effect: Allow\n    Action: '*'\n    Resource: '*'\n",
        [("iam-admin-grant", BLOCK)],
    ),
    "multi-document": (
        "a: 1\n---\nStatement:\n  - Effect: Allow\n    Action: '*'\n    Resource: '*'\n",
        [("iam-admin-grant", BLOCK)],
    ),
    "principal": (
        "Statement:\n  - Effect: Allow\n    Principal: '*'\n    Action: s3:GetObject\n",
        [("iam-principal-wildcard", BLOCK)],
    ),
    "sam-inline-policy": (
        "Policies:\n  - Statement:\n      - Effect: Allow\n        Action: s3:*\n        Resource: '*'\n",
        [("iam-service-wildcard", BLOCK)],
    ),
    "json-in-yaml-string": (
        'policy: \'{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\'\n',
        [("iam-admin-grant", BLOCK)],
    ),
    "serverless": (
        "provider:\n  iam:\n    role:\n      statements:\n        - Effect: Allow\n          Action: '*'\n          Resource: '*'\n",
        [("iam-admin-grant", BLOCK)],
    ),
}
YAML_ALLOWED = {
    "reference-action": "Statement:\n  - Effect: Allow\n    Action: !Ref Act\n    Resource: !Sub '*'\n",
    "scoped": "Statement:\n  - Effect: Allow\n    Action:\n      - s3:GetObject\n    Resource: arn:aws:s3:::b/*\n",
    "deny": "Statement:\n  - Effect: Deny\n    Action: '*'\n    Resource: '*'\n",
    "not-a-policy": "name: x\nsteps:\n  - run: echo statement\n",
    "unrelated-parse-error": "statement: [a: b]\n",
}


@pytest.mark.parametrize("case", sorted(YAML_CASES))
def test_yaml_grant_is_judged_as_the_document_says(case: str) -> None:
    text, expected = YAML_CASES[case]
    assert rules("p.yaml", text) == expected


@pytest.mark.parametrize("case", sorted(YAML_ALLOWED))
def test_yaml_that_is_not_a_broad_grant_is_allowed(case: str) -> None:
    assert rules("p.yml", YAML_ALLOWED[case]) == []


def test_a_yaml_finding_is_reported_at_the_value_it_is_about() -> None:
    text = "Statement:\n  - Effect: Allow\n    Action:\n      - '*'\n    Resource: '*'\n"
    assert [f.line for f in found({"p.yaml": text})] == [4]

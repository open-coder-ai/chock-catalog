"""iam-policy-scan: what is read, what is refused for being unreadable, and what is left alone."""

from __future__ import annotations

import pytest
from policies import iamkit
from policies.iamkit import found, gate, rules

BLOCK = "block"
GRANT = '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("a/b/policy.json", "json"),
        ("cdk.jsonc", "json"),
        ("Policy.JSON", "json"),
        ("x.yaml", "yaml"),
        ("x.YML", "yaml"),
        ("main.tf", "hcl"),
        ("prod.tfvars", "hcl"),
        ("stack.hcl", "hcl"),
        ("main.tf.json", "tfjson"),
        ("prod.auto.tfvars.json", "tfjson"),
        ("main.bicep", "bicep"),
        ("stack.template", "template"),
        ("win\\dir\\policy.json", "json"),
        ("README.md", None),
        ("main.py", None),
        ("noextension", None),
    ],
)
def test_the_file_name_decides_how_a_file_is_read(name: str, kind: str | None) -> None:
    assert gate.scan_file.__globals__["kind_of"](name) == kind


def test_a_template_file_is_json_or_yaml_by_its_first_character() -> None:
    assert rules("stack.template", GRANT) == [("iam-admin-grant", BLOCK)]
    assert rules("stack.template", "﻿  \n" + GRANT) == [("iam-admin-grant", BLOCK)]
    yaml = "Statement:\n  - Effect: Allow\n    Action: '*'\n    Resource: '*'\n"
    assert rules("stack.template", yaml) == [("iam-admin-grant", BLOCK)]


def test_a_file_is_opened_only_when_it_mentions_something_a_grant_is_made_of() -> None:
    assert rules("big.json", '{"a": [' + ",".join(["1"] * 1000) + "]}") == []
    assert rules("big.json", "not json at all and no grant words") == []


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("p.json", '{"Effect": "Allow", '),
        ("p.json", '{"Effect": "Allow", "Action": NaN}'),
        ("p.json", '{"Effect": "Allow", "__proto__": 1}'),
        ("p.yaml", "Effect: Allow\nAction: *\n"),
        ("p.yaml", "a: &a\n  b: *a\nEffect: Allow\n"),
        ("p.yaml", "Effect: Allow\nx: *missing\n"),
        ("p.yaml", "Effect: Allow\nb: &x [*x]\n"),
        ("p.yaml", "Statement:\n\t- Effect: Allow\n"),
        ("p.yaml", "base: &b {a: 1}\nEffect: Allow\nc:\n  <<: 5\n"),
        ("p.yaml", "base: &b [1]\nEffect: Allow\nc:\n  <<: *b\n"),
        ("main.tf", 'Effect = "Allow\n'),
        ("main.tf.json", '{"Effect": "Allow", '),
    ],
)
def test_a_file_that_names_a_grant_and_cannot_be_read_is_refused(name: str, text: str) -> None:
    assert [f.rule for f in found({name: text})] == ["iam-unreadable"]


def test_the_unreadable_finding_is_the_same_before_and_after_so_an_old_one_is_not_new() -> None:
    first = found({"p.json": '{"Effect": "Allow", '})
    second = found({"p.json": '{"Effect": "Allow", "x": '})
    assert first[0].key == second[0].key


def test_aliases_that_expand_past_the_budget_are_refused() -> None:
    lines = ["a0: &a0 [x, x]"] + [f"a{i}: &a{i} [*a{i - 1}, *a{i - 1}]" for i in range(1, 30)]
    text = "Effect: Allow\n" + "\n".join(lines) + "\n"
    assert [f.rule for f in found({"bomb.yaml": text})] == ["iam-unreadable"]


def test_nesting_deeper_than_the_gate_reads_is_refused() -> None:
    text = '{"Effect": "Allow", "x": ' + "[" * 150 + "]" * 150 + "}"
    deep = rules("deep.json", text)
    assert deep in ([("iam-unreadable", BLOCK)], [])
    nested = {"a": 1}
    for _ in range(210):
        nested = {"a": nested}
    walker = iamkit.gate.scan_file.__globals__["Scan"]("x.json")
    with pytest.raises(ValueError, match="deeper"):
        walker.walk(nested)


def test_a_repeated_policy_key_is_refused_wherever_it_hides_a_value() -> None:
    assert (
        next(f.rule for f in found({"p.json": '{"Statement": [{"Effect": "Deny", "Effect": "Allow", "Action": "*"}]}'}))
        == "iam-duplicate-key"
    )
    assert [
        f.rule for f in found({"p.yaml": "Statement:\n  - Effect: Deny\n    Effect: Allow\n    Action: s3:Get*\n"})
    ] == ["iam-duplicate-key"]
    assert [f.rule for f in found({"p.json": '{"Effect": "Allow", "Resource": "a", "Resource": "b"}'})] == [
        "iam-duplicate-key"
    ]


def test_a_repeated_key_nobody_reads_policies_by_is_left_alone() -> None:
    assert rules("p.json", '{"Effect": "Allow", "Description": "a", "Description": "b"}') == []


def test_a_repeated_key_in_a_json_string_is_refused_too() -> None:
    inner = '{"Statement": [{"Effect": "Allow", "Effect": "Deny"}]}'
    assert [f.rule for f in found({"p.json": '{"p": ' + __import__("json").dumps(inner) + "}"})] == [
        "iam-duplicate-key"
    ]


def test_a_unicode_bom_and_crlf_line_endings_are_read() -> None:
    text = "﻿Statement:\r\n  - Effect: Allow\r\n    Action: '*'\r\n    Resource: '*'\r\n"
    assert rules("p.yaml", text) == [("iam-admin-grant", BLOCK)]


def test_the_checks_do_not_depend_on_the_path_being_relative() -> None:
    assert rules("/work/repo/infra/p.json", GRANT) == [("iam-admin-grant", BLOCK)]

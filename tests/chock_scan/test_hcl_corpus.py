"""chock_scan.hcl and hcl_json on real Terraform, OpenTofu and Packer files (corpus/hcl/NOTICE.md names each source)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from chock_scan.hclload import CORPUS

FILES = sorted(p for p in CORPUS.rglob("*") if p.is_file() and p.name != "NOTICE.md")
VALID = [p for p in FILES if "invalid" not in p.parts]
INVALID = [p for p in FILES if "invalid" in p.parts]
EMPTY = {
    "valid-files-empty.tf.json",
    "comments-hash_comment.hcl",
    "comments-multiline_comment.hcl",
    "comments-slash_comment.hcl",
}


def read(m: SimpleNamespace, path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    if path.name.endswith(".json"):
        return m.hcl_json.parse_json(text)
    return m.hcl.parse(text)


def by_name(m: SimpleNamespace, rel: str) -> object:
    return read(m, CORPUS / rel)


def test_the_corpus_is_what_the_notice_lists() -> None:
    assert len(VALID) == 38
    assert len(INVALID) == 9
    notice = (CORPUS / "NOTICE.md").read_text(encoding="utf-8")
    assert {p.relative_to(CORPUS).parts[0] for p in FILES} == {
        line.split("`")[1].rstrip("/") for line in notice.splitlines() if line.startswith("| `")
    }


@pytest.mark.parametrize("path", VALID, ids=[p.relative_to(CORPUS).as_posix() for p in VALID])
def test_every_real_file_parses_quickly_and_is_not_empty(m: SimpleNamespace, path: Path) -> None:
    started = time.perf_counter()
    root = read(m, path)
    assert time.perf_counter() - started < 2
    assert bool(root.blocks or root.attributes) is (path.name not in EMPTY)


@pytest.mark.parametrize("path", INVALID, ids=[p.relative_to(CORPUS).as_posix() for p in INVALID])
def test_every_file_with_a_syntax_error_raises(m: SimpleNamespace, path: Path) -> None:
    with pytest.raises(m.hcl.HclError):
        read(m, path)


def test_the_spec_suite_heredocs_match_hcls_expected_values(m: SimpleNamespace) -> None:
    root = by_name(m, "hcl-specsuite/valid/expressions-heredoc.hcl")
    values = {a.key: a.value for a in root.attributes}
    c = m.hcl.COMPUTED
    assert values["normal"] == {
        "basic": "Foo\nBar\nBaz\n", "indented": "    Foo\n    Bar\n    Baz\n",
        "indented_more": "    Foo\n      Bar\n    Baz\n", "interp": c,
        "newlines_between": "Foo\n\nBar\n\nBaz\n", "indented_newlines_between": "    Foo\n\n    Bar\n\n    Baz\n",
        "marker_at_suffix": "    NOT EOT\n",
    }  # fmt: skip
    assert values["flush"] == {
        "basic": "Foo\nBar\nBaz\n", "indented": "Foo\nBar\nBaz\n", "indented_more": "Foo\n  Bar\nBaz\n",
        "indented_less": "  Foo\nBar\n  Baz\n", "interp": c, "interp_indented_more": c, "interp_indented_less": c,
        "tabs": "Foo\n Bar\n Baz\n", "unicode_spaces": "\u2003Foo (there's two \"em spaces\" before Foo there)\nBar\nBaz\n",
        "newlines_between": "Foo\n\nBar\n\nBaz\n", "indented_newlines_between": "Foo\n\nBar\n\nBaz\n",
    }  # fmt: skip


def test_the_spec_suite_literals(m: SimpleNamespace) -> None:
    root = by_name(m, "hcl-specsuite/valid/expressions-primitive_literals.hcl")
    values = {a.key: a.value for a in root.attributes}
    assert values["whole_number"] == 5
    assert values["fractional_number"] == 3.2
    assert values["string_unicode_bmp"] == "ЖЖ"
    assert (values["true"], values["false"], values["null"]) == (True, False, None)


def test_a_heredoc_policy_is_a_literal_a_caller_can_load_as_json(m: SimpleNamespace) -> None:
    root = by_name(m, "terraform-aws-iam/examples-iam-policy-main.tf")
    policies = {b.labels: b.attr("policy") for b in m.hcl.walk(root) if b.attr("policy")}
    literal = policies[("iam_policy",)]
    assert literal.line == 26
    assert json.loads(literal.value)["Statement"][0]["Action"] == ["ec2:Describe*"]
    assert policies[("iam_policy_from_data_source",)].value is m.hcl.COMPUTED


def test_module_variables_are_computed_so_a_caller_can_fail_closed(m: SimpleNamespace) -> None:
    root = by_name(m, "terraform-aws-s3-bucket/main.tf")
    (pab,) = [b for b in root.blocks if b.labels[:1] == ("aws_s3_bucket_public_access_block",)]
    assert pab.attr("block_public_acls").expr == "var.block_public_acls"
    assert pab.attr("block_public_acls").computed
    assert pab.attr("count").computed


def test_packer_imds_settings_are_literals(m: SimpleNamespace) -> None:
    root = by_name(m, "packer-plugin-amazon/ubuntu-imdsv2-enabled.pkr.hcl")
    (source,) = [b for b in m.hcl.walk(root) if b.type == "source"]
    assert source.labels == ("amazon-ebs", "imds-example")
    assert source.children("metadata_options")[0].attr("http_tokens").value == "required"
    (shell,) = [b for b in m.hcl.walk(root) if b.type == "provisioner"]
    assert '"X-aws-ec2-metadata-token: $TOKEN"' in shell.attr("inline").value[0]


def test_tf_json_variables_are_one_label_blocks(m: SimpleNamespace) -> None:
    root = by_name(m, "opentofu/valid/valid-files-variables.tf.json")
    assert {b.type for b in root.blocks} == {"variable"}
    assert all(len(b.labels) == 1 for b in root.blocks)
    assert ("cheese_pizza",) in {b.labels for b in root.blocks}


def test_dynamic_blocks_are_returned_as_written(m: SimpleNamespace) -> None:
    root = by_name(m, "terraform-aws-security-group/main.tf")
    dynamics = [b for b in m.hcl.walk(root) if b.type == "dynamic"]
    assert dynamics
    for block in dynamics:
        assert len(block.labels) == 1
        assert block.attr("for_each").computed

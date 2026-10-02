"""chock_scan.hcl_json: Terraform/Packer JSON syntax read into the same Blocks, and every refusal, named."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

TF = """\
{
  "//": "a comment property, skipped",
  "resource": {
    "aws_security_group": {
      "web": {
        "name": "web-${var.env}",
        "ingress": [
          {"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
          {"from_port": 443, "cidr_blocks": ["10.0.0.0/8"]}
        ],
        "dynamic": {"egress": {"for_each": "${var.rules}", "content": {"cidr_blocks": "${egress.value}"}}},
        "provisioner": {"local-exec": {"command": "echo $${HOME}"}},
        "tags": {"Team": "x", "Cost": 1.5, "On": true, "Off": null}
      }
    }
  },
  "terraform": {"backend": {"s3": {"encrypt": false}}, "required_version": ">= 1.5"},
  "provider": {"aws": [{"region": "eu-west-1"}, {"alias": "us", "region": "us-east-1"}]},
  "locals": {"admins": ["a", "b"]},
  "variable": {"db_password": {"default": "hunter2-not-real"}}
}
"""


def summary(m: SimpleNamespace, root: object) -> list[tuple[str, tuple[str, ...], int]]:
    return [(b.type, b.labels, b.line) for b in m.hcl.walk(root)]


def test_blocks_by_label_table_with_lines(m: SimpleNamespace) -> None:
    root = m.hcl_json.parse_json(TF)
    assert (root.type, root.labels, root.line, root.attributes) == ("", (), 1, ())
    assert summary(m, root) == [
        ("resource", ("aws_security_group", "web"), 5),
        ("ingress", (), 8),
        ("ingress", (), 9),
        ("dynamic", ("egress",), 11),
        ("content", (), 11),
        ("provisioner", ("local-exec",), 12),
        ("tags", (), 13),
        ("terraform", (), 17),
        ("backend", ("s3",), 17),
        ("provider", ("aws",), 18),
        ("provider", ("aws",), 18),
        ("locals", (), 19),
        ("variable", ("db_password",), 20),
    ]


def test_attributes_carry_values_raw_json_and_lines(m: SimpleNamespace) -> None:
    root = m.hcl_json.parse_json(TF)
    web = root.blocks[0]
    assert [a.key for a in web.attributes] == ["name", "ingress", "dynamic", "provisioner", "tags"]
    name = web.attr("name")
    assert (name.value, name.expr, name.line) == (m.hcl.COMPUTED, '"web-${var.env}"', 6)
    assert web.attr("ingress").value == (
        {"from_port": 22, "cidr_blocks": ("0.0.0.0/0",)},
        {"from_port": 443, "cidr_blocks": ("10.0.0.0/8",)},
    )
    assert json.loads(web.attr("ingress").expr)[1]["from_port"] == 443
    assert web.attr("tags").value == {"Team": "x", "Cost": 1.5, "On": True, "Off": None}
    assert web.children("provisioner")[0].attr("command").value == "echo ${HOME}"
    assert web.children("dynamic")[0].attr("for_each").computed
    assert web.children("ingress")[0].attr("cidr_blocks").value == ("0.0.0.0/0",)
    assert root.blocks[1].children("backend")[0].attr("encrypt").value is False
    assert root.blocks[3].attr("region").value == "us-east-1"
    assert root.blocks[4].attr("admins").value == ("a", "b")


def test_a_scalar_or_mixed_list_is_an_attribute_only(m: SimpleNamespace) -> None:
    root = m.hcl_json.parse_json('{"locals": {"a": [1, {"b": 2}], "c": [], "d": "s", "e": {"provisioner": 1}}}')
    (local,) = root.blocks
    assert [b.type for b in local.blocks] == ["e"]
    assert local.blocks[0].blocks == ()


def test_packer_labels(m: SimpleNamespace) -> None:
    src = '{"source": {"amazon-ebs": {"x": {"ami_name": "a"}}}, "build": {"sources": ["source.amazon-ebs.x"], "post-processor": {"manifest": {}}}}'
    root = m.hcl_json.parse_json(src, m.hcl_json.PACKER)
    assert summary(m, root) == [
        ("source", ("amazon-ebs", "x"), 1),
        ("build", (), 1),
        ("post-processor", ("manifest",), 1),
    ]


def test_an_empty_object_and_comment_only_object(m: SimpleNamespace) -> None:
    assert m.hcl_json.parse_json("\ufeff {} \n").blocks == ()
    assert m.hcl_json.parse_json('{"//": "x"}').blocks == ()


@pytest.mark.parametrize(
    ("src", "message"),
    [
        ("", "expected a JSON value"),
        ("  \n", "expected a JSON value"),
        ("null", "not null"),
        ('"x"', "the file: expected an object or an array of objects"),
        ("[1]", "the file: expected an object or an array of objects"),
        ("{} {}", "extra data"),
        ("{", "Expecting property name"),
        ('{"resource": {"a": {"b": {}}},}', "Expecting property name"),
        ('{"bogus": {}}', "unknown top-level block type 'bogus'"),
        ('{"builders": []}', "unknown top-level block type"),
        ('{"resource": 1}', "resource labels: expected an object or an array of objects"),
        ('{"resource": {"a": "b"}}', "resource labels: expected an object"),
        ('{"resource": {"a": {"b": 1}}}', "a body: expected an object"),
        ('{"resource": {"a": {"b": [1]}}}', "a body: expected an object"),
        ('{"resource": []}', "resource: missing block label"),
        ('{"resource": {}}', "resource: missing block label"),
        ('{"resource": {"a": {}}}', "resource: missing block label"),
        ('{"resource": {"a": null}}', "resource: missing block label"),
        ('{"resource": [1]}', "resource labels: expected an object"),
        ('{"locals": {"a": 1, "a": 2}}', "duplicate key 'a'"),
        ('{"locals": {"a": {"b": 1, "b": 1}}}', "duplicate key in an object"),
        ('{"resource": {"t": {"n": [[{"a": 1}, {"a": 2}]]}}}', "duplicate key 'a'"),
        ('{"locals": {"a": NaN}}', "NaN is not JSON"),
        ('{"locals": {"a": -Infinity}}', "Infinity is not JSON"),
        ('{"locals": {"a": "\\u0000"}}' + "\x00", "extra data"),
        ('{"locals": {"a": "tab\there"}}', "Invalid control character"),
        ('{"locals": {"a": ' + "1" * 5000 + "}}", "digits"),
        ("{'a': 1}", "Expecting property name"),
    ],
)  # fmt: skip
def test_unreadable_json_raises(m: SimpleNamespace, src: str, message: str) -> None:
    with pytest.raises(m.hcl.HclError, match=message):
        m.hcl_json.parse_json(src)


def test_errors_carry_the_line(m: SimpleNamespace) -> None:
    with pytest.raises(m.hcl.HclError) as caught:
        m.hcl_json.parse_json('{\n"locals": {\n"a": 1,\n"a": 2}}')
    assert caught.value.line == 4
    with pytest.raises(m.hcl.HclError) as caught:
        m.hcl_json.parse_json('{\n\n "x": }')
    assert caught.value.line == 3


def test_nesting_is_capped(m: SimpleNamespace) -> None:
    cap = m.hcl_lex.MAX_DEPTH
    ok = '{"locals": {"a": ' + "[" * (cap - 3) + "]" * (cap - 3) + "}}"
    assert m.hcl_json.parse_json(ok).blocks[0].attributes[0].key == "a"
    for deep in ("[" * cap + "]" * cap, '{"b": ' * cap + "1" + "}" * cap):
        with pytest.raises(m.hcl.HclError, match="nested deeper than 64"):
            m.hcl_json.parse_json('{"locals": {"a": ' + deep + "}}")
    with pytest.raises(m.hcl.HclError, match="nested too deep"):
        m.hcl_json.parse_json('{"locals": {"a": ' + "[" * 100_000 + "]" * 100_000 + "}}")


def test_the_size_cap(m: SimpleNamespace) -> None:
    with pytest.raises(m.hcl.HclError, match="larger than"):
        m.hcl_json.parse_json(" " * (m.hcl_lex.MAX_CHARS + 1))


def test_repeated_keys_spell_more_blocks_at_the_top_and_label_levels(m: SimpleNamespace) -> None:
    src = '[{"locals": {"a": 1}}, {"locals": {"b": 2}, "resource": [{"t": {"x": {}}}, {"t": {"y": {}}}]}]'
    root = m.hcl_json.parse_json(src)
    assert summary(m, root) == [
        ("locals", (), 1),
        ("locals", (), 1),
        ("resource", ("t", "x"), 1),
        ("resource", ("t", "y"), 1),
    ]


def test_a_body_split_across_an_array_is_merged_and_null_is_an_empty_block(m: SimpleNamespace) -> None:
    src = '{"resource": {"t": {"n": [[{"type": "ingress"}, {"cidr": "0.0.0.0/0"}], null]}}}'
    first, second = m.hcl_json.parse_json(src).blocks
    assert {a.key: a.value for a in first.attributes} == {"type": "ingress", "cidr": "0.0.0.0/0"}
    assert (second.labels, second.attributes) == (("t", "n"), ())


def test_a_labelled_block_that_does_not_fit_its_labels_is_still_a_block(m: SimpleNamespace) -> None:
    src = '{"resource": {"t": {"n": {"provisioner": {"local-exec": {"command": "sh"}, "when": "destroy"}}}}}'
    (block,) = m.hcl_json.parse_json(src).blocks[0].children("provisioner")
    assert block.labels == ()
    assert block.attr("when").value == "destroy"
    assert block.children("local-exec")[0].attr("command").value == "sh"


def test_object_value_keys_are_templates_and_nfc(m: SimpleNamespace) -> None:
    def value(obj: str) -> object:
        return m.hcl_json.parse_json('{"locals": {"m": ' + obj + "}}").blocks[0].attr("m").value

    assert value('{"//": 1, "$${a}": 2}') == {"//": 1, "${a}": 2}
    assert value('{"${var.k}": 1}') is m.hcl.COMPUTED
    assert value('{"e\\u0301": 1, "\\u00e9": 2}') is m.hcl.COMPUTED
    assert value('"fals\\u0065\\u0300"') == "falsè"
    assert value('"${"') is m.hcl.COMPUTED


def test_the_schema_decides_nested_labels(m: SimpleNamespace) -> None:
    tf = '{"resource": {"aws_codebuild_project": {"p": {"source": {"type": "GITHUB"}}}}}'
    (source,) = m.hcl_json.parse_json(tf).blocks[0].children("source")
    assert (source.labels, source.attr("type").value) == ((), "GITHUB")
    check = '{"check": {"c": {"data": {"http": {"h": {"url": "x"}}}}}}'
    assert m.hcl_json.parse_json(check).blocks[0].children("data")[0].labels == ("http", "h")
    packer = '{"build": {"source": {"amazon-ebs.x": {"name": "n"}}}}'
    assert m.hcl_json.parse_json(packer, m.hcl_json.PACKER).blocks[0].children("source")[0].labels == ("amazon-ebs.x",)
    with pytest.raises(m.hcl.HclError, match="unknown top-level block type 'build'"):
        m.hcl_json.parse_json(packer)

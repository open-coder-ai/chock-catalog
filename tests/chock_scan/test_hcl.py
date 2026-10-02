"""chock_scan.hcl: blocks, labels, attributes, literal values and COMPUTED, and every refusal, named."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

SG = """\
# a security group the way wave-3 rules will read it
resource "aws_security_group" "web" {
  name = "web"   // trailing comment
  ingress {
    from_port   = 22
    cidr_blocks = ["0.0.0.0/0", "::/0"]
  }
  ingress { cidr_blocks = [var.cidr] }
  dynamic "egress" {
    for_each = var.rules
    content {
      cidr_blocks = egress.value.cidrs
    }
  }
}

data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
"""


def attrs(block: object) -> dict[str, object]:
    return {a.key: a.value for a in block.attributes}


def test_blocks_labels_lines_and_nesting(m: SimpleNamespace) -> None:
    root = m.hcl.parse(SG)
    assert (root.type, root.labels, root.line, root.attributes) == ("", (), 1, ())
    assert [(b.type, b.labels, b.line) for b in m.hcl.walk(root)] == [
        ("resource", ("aws_security_group", "web"), 2),
        ("ingress", (), 4),
        ("ingress", (), 8),
        ("dynamic", ("egress",), 9),
        ("content", (), 11),
        ("data", ("aws_iam_policy_document", "p"), 17),
        ("statement", (), 18),
    ]
    sg = root.blocks[0]
    assert attrs(sg) == {"name": "web"}
    first, second = sg.children("ingress")
    assert attrs(first) == {"from_port": 22, "cidr_blocks": ("0.0.0.0/0", "::/0")}
    assert attrs(second) == {"cidr_blocks": (m.hcl.COMPUTED,)}
    assert second.attr("cidr_blocks").computed
    assert not first.attr("cidr_blocks").computed
    assert first.attr("missing") is None
    assert sg.children("nothing") == ()
    (dynamic,) = sg.children("dynamic")
    assert dynamic.attr("for_each").value is m.hcl.COMPUTED
    assert dynamic.children("content")[0].attr("cidr_blocks").expr == "egress.value.cidrs"
    statement = root.blocks[1].blocks[0]
    assert attrs(statement) == {"actions": ("*",), "resources": ("*",)}
    assert statement.attr("actions").line == 19


def test_attribute_lines_and_raw_expression_text(m: SimpleNamespace) -> None:
    root = m.hcl.parse('a = foo(1,\n  2) # c\nb = [\n  "x", # in\n  "y",\n]\n')
    a, b = root.attributes
    assert (a.key, a.expr, a.line) == ("a", "foo(1,\n  2)", 1)
    assert (b.expr, b.line, b.value) == ('[\n  "x", # in\n  "y",\n]', 3, ("x", "y"))


@pytest.mark.parametrize(
    ("expr", "want"),
    [
        ('"s"', "s"),
        ("42", 42),
        ("-7", -7),
        ("1.5", 1.5),
        ("2e3", 2000.0),
        ("true", True),
        ("false", False),
        ("null", None),
        ("[]", ()),
        ("{}", {}),
        ('[1, "a", [true], {k = null}]', (1, "a", (True,), {"k": None})),
        ('{a = 1, "b-c": 2\n d = [3]\n}', {"a": 1, "b-c": 2, "d": (3,)}),
        ('{\n  a = 1,\n\n  b = 2,\n}', {"a": 1, "b": 2}),
        ('[\n  1\n  ,\n  2\n]', (1, 2)),
        ("<<EOT\n{\"Action\": \"*\"}\nEOT", '{"Action": "*"}\n'),
    ],
)  # fmt: skip
def test_literals_are_values(m: SimpleNamespace, expr: str, want: object) -> None:
    attr = m.hcl.parse(f"x = {expr}\n").attributes[0]
    assert attr.value == want
    assert not attr.computed


@pytest.mark.parametrize(
    "expr",
    [
        "var.x", "local.y[0]", "foo()", "jsonencode({a = 1})", '"${var.a}"', '"a" == "b"', "1 + 2",
        "true ? 1 : 2", "[for x in y : x]", "{for k, v in m : k => v}", "(1)", '"a".b', "!true", "-x",
        "count.index", "each.value", "[1, 2][0]", "{a = 1}.a", "<<EOT\n${x}\nEOT", "- 5 - 1", "x-1",
    ],
)  # fmt: skip
def test_anything_but_a_literal_is_computed(m: SimpleNamespace, expr: str) -> None:
    attr = m.hcl.parse(f"x = {expr}\n").attributes[0]
    assert attr.value is m.hcl.COMPUTED
    assert attr.computed
    assert attr.expr == expr


@pytest.mark.parametrize(
    ("expr", "want"),
    [
        ('["*", var.x]', ("*", "C")),
        ("[var.x, 1 + 2, f(a, b), [1, x]]", ("C", "C", "C", (1, "C"))),
        ('{a = var.x, b = "s", c = x ? 1 : 2}', {"a": "C", "b": "s", "c": "C"}),
        ('{a = {b = [c]}}', {"a": {"b": ("C",)}}),
        ("[\n  var.x\n  , 2\n]", ("C", 2)),
        ("{a = }", {"a": "C"}),
    ],
)  # fmt: skip
def test_computed_parts_stay_in_place_inside_literals(m: SimpleNamespace, expr: str, want: object) -> None:
    attr = m.hcl.parse(f"x = {expr}\n").attributes[0]
    assert _mark(attr.value, m.hcl.COMPUTED) == want
    assert attr.computed


@pytest.mark.parametrize(
    "expr",
    ["{(var.k) = 1}", "{a = 1, a = 2}", "{var.k = 1}", "{1 = 2}", "{for = 1}", '{"${k}" = 1}'],
)
def test_an_object_whose_keys_cannot_be_known_is_computed_whole(m: SimpleNamespace, expr: str) -> None:
    root = m.hcl.parse(f"x = {expr}\ny = 1\n")
    assert root.attributes[0].value is m.hcl.COMPUTED
    assert root.attributes[1].value == 1


def test_malformed_tuples_are_computed_not_guessed(m: SimpleNamespace) -> None:
    assert m.hcl.parse("x = [,]\n").attributes[0].value == (m.hcl.COMPUTED,)
    assert m.hcl.parse("x = [for]\n").attributes[0].value is m.hcl.COMPUTED


def test_one_line_blocks_labels_by_identifier_and_escaped_strings(m: SimpleNamespace) -> None:
    root = m.hcl.parse('a {}\nb x "y\\"z" { k = 1 }\nc {\n}\nd "" {}')
    assert [(b.type, b.labels, attrs(b)) for b in root.blocks] == [
        ("a", (), {}), ("b", ("x", 'y"z'), {"k": 1}), ("c", (), {}), ("d", ("",), {}),
    ]  # fmt: skip


def test_a_tfvars_file_is_root_attributes(m: SimpleNamespace) -> None:
    root = m.hcl.parse('\ufeffregion = "eu-west-1"\r\ntags = { team = "x" }\r\n')
    assert attrs(root) == {"region": "eu-west-1", "tags": {"team": "x"}}
    assert root.blocks == ()
    assert root.attributes[1].line == 2


@pytest.mark.parametrize("src", ["", "\n\n", "# only a comment\n", "\ufeff", "/* */"])
def test_an_empty_file_is_an_empty_root(m: SimpleNamespace, src: str) -> None:
    root = m.hcl.parse(src)
    assert (root.attributes, root.blocks) == ((), ())


@pytest.mark.parametrize(
    ("src", "message"),
    [
        ("a = 1 b = 2", "a second '=' after a ="),
        ("a = 1\na = 2", "attribute 'a' defined twice"),
        ("a =\n1", "missing expression"),
        ("a = ", "missing expression"),
        ("a = (1", "unclosed bracket"),
        ("a = (1]", r"unbalanced '\]'"),
        ("a = 1)", r"unbalanced '\)'"),
        ("r {", "block r is never closed"),
        ("r {\n a = [1\n}", r"unbalanced '\}'"),
        ("}", r"unexpected '\}'"),
        ("r { } x", "'x' after its closing brace"),
        ("r { } r2 {}", "'r2' after its closing brace"),
        ('r "${x}" {}', "expected a label"),
        ("r <<EOT\nx\nEOT\n{}", "expected a label"),
        ("r 1 {}", "expected a label"),
        ("r\n{}", "expected a label"),
        ("r", "expected a label"),
        ('"a" = 1', "expected an attribute or block name"),
        ("= 1", "expected an attribute or block name"),
        ("{a = 1}", "expected an attribute or block name"),
    ],
)  # fmt: skip
def test_text_terraform_would_refuse_raises(m: SimpleNamespace, src: str, message: str) -> None:
    with pytest.raises(m.hcl.HclError, match=message):
        m.hcl.parse(src)


def test_the_depth_caps_raise(m: SimpleNamespace) -> None:
    cap = m.hcl_lex.MAX_DEPTH
    nested: object = ()
    for _ in range(cap - 1):
        nested = (nested,)
    assert m.hcl.parse("x = " + "[" * cap + "]" * cap).attributes[0].value == nested
    with pytest.raises(m.hcl.HclError, match="brackets nested deeper than 64"):
        m.hcl.parse("x = " + "[" * (cap + 1) + "]" * (cap + 1))
    nested = "b {\n" * cap + "}\n" * cap
    assert len(list(m.hcl.walk(m.hcl.parse(nested)))) == cap
    with pytest.raises(m.hcl.HclError, match="blocks nested deeper than 64"):
        m.hcl.parse("b {\n" * (cap + 1) + "}\n" * (cap + 1))


def test_is_computed_looks_inside_tuples_and_dicts(m: SimpleNamespace) -> None:
    c = m.hcl.COMPUTED
    assert m.hcl.is_computed(c)
    assert m.hcl.is_computed((1, (2, {"a": c})))
    assert not m.hcl.is_computed((1, {"a": [c]}))  # lists are not values the scanner produces
    assert not m.hcl.is_computed({"a": "b"})
    assert not m.hcl.is_computed(None)


def test_the_public_names(m: SimpleNamespace) -> None:
    assert m.hcl.HclError is m.hcl_lex.HclError
    assert m.hcl.COMPUTED is m.hcl_lex.COMPUTED
    assert isinstance(m.hcl.COMPUTED, m.hcl.Computed)
    assert set(m.hcl.__all__) == {
        "COMPUTED",
        "Attribute",
        "Block",
        "Computed",
        "HclError",
        "is_computed",
        "parse",
        "walk",
    }
    assert all(hasattr(m.hcl, name) for name in m.hcl.__all__)


def _mark(value: object, computed: object) -> object:
    if isinstance(value, tuple):
        return tuple(_mark(v, computed) for v in value)
    if isinstance(value, dict):
        return {k: _mark(v, computed) for k, v in value.items()}
    return "C" if value is computed else value

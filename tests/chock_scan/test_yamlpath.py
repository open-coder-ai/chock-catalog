"""chock_scan.yamlpath: what the scanner reports, case by case, for the shapes CI and IaC files use."""

from __future__ import annotations

import ast
import sys
from types import ModuleType

import pytest
from chock_scan.yamlkit import triples, value_at
from trees import ROOT

BOM = chr(0xFEFF)


def test_block_mappings_and_sequences_give_key_paths_with_lines(yp: ModuleType) -> None:
    text = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - run: make\n"
    found = yp.scan(text)
    assert [(n.path, n.value, n.line, n.kind) for n in found] == [
        ((), "", 1, "map"),
        (("jobs",), "", 2, "map"),
        (("jobs", "build"), "", 3, "map"),
        (("jobs", "build", "steps"), "", 4, "seq"),
        (("jobs", "build", "steps", 0), "", 4, "map"),
        (("jobs", "build", "steps", 0, "uses"), "actions/checkout@v4", 4, "plain"),
        (("jobs", "build", "steps", 1), "", 5, "map"),
        (("jobs", "build", "steps", 1, "run"), "make", 5, "plain"),
    ]
    path, value, line, *_ = found[5]
    assert (path, value, line) == (("jobs", "build", "steps", 0, "uses"), "actions/checkout@v4", 4)
    assert {n.doc for n in found} == {0}


def test_a_sequence_may_sit_at_its_keys_indent(yp: ModuleType) -> None:
    assert triples(yp, "a:\n- x\n- y\nb: 1\n") == [
        ((), "", "map"),
        (("a",), "", "seq"),
        (("a", 0), "x", "plain"),
        (("a", 1), "y", "plain"),
        (("b",), "1", "plain"),
    ]


def test_compact_nested_collections_inside_sequences(yp: ModuleType) -> None:
    assert triples(yp, "- - a\n  - b\n-   k: v\n    j: w\n") == [
        ((), "", "seq"),
        ((0,), "", "seq"),
        ((0, 0), "a", "plain"),
        ((0, 1), "b", "plain"),
        ((1,), "", "map"),
        ((1, "k"), "v", "plain"),
        ((1, "j"), "w", "plain"),
    ]


def test_flow_collections_nest_span_lines_and_report_empty_ones(yp: ModuleType) -> None:
    text = 'a: {b: [1, "two", {c: d}], e: {}, f: [], g, h:}\nk: [\n  x,  # one\n  y,\n]\n'
    assert triples(yp, text) == [
        ((), "", "map"),
        (("a",), "", "map"),
        (("a", "b"), "", "seq"),
        (("a", "b", 0), "1", "plain"),
        (("a", "b", 1), "two", "double"),
        (("a", "b", 2), "", "map"),
        (("a", "b", 2, "c"), "d", "plain"),
        (("a", "e"), "", "map"),
        (("a", "f"), "", "seq"),
        (("a", "g"), "", "plain"),
        (("a", "h"), "", "plain"),
        (("k",), "", "seq"),
        (("k", 0), "x", "plain"),
        (("k", 1), "y", "plain"),
    ]
    assert triples(yp, "{\"a\":1, 'b' : 2, c: !t , d: &n }") == [
        ((), "", "map"),
        (("a",), "1", "plain"),
        (("b",), "2", "plain"),
        (("c",), "", "plain"),
        (("d",), "", "plain"),
    ]


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ('a: "x # y"', "x # y"),
        ("a: 'x # y' # real", "x # y"),
        ("a: x#y", "x#y"),
        ("a: x # y", "x"),
        ("a: x\t# y", "x"),
        ("a: [x#y, z] # c", ""),
        ("a: http://h:8080/p#frag", "http://h:8080/p#frag"),
        ("a: |  # header comment\n  # not a comment\n", "# not a comment\n"),
    ],
)
def test_a_hash_is_a_comment_only_after_a_blank_and_outside_quotes(yp: ModuleType, text: str, value: str) -> None:
    assert value_at(yp, text, ("a",)) == value


def test_a_key_hidden_by_quotes_or_escapes_is_still_its_key(yp: ModuleType) -> None:
    text = '"perm\\x69ssions": write-all\n\'on\': push\n"a b" : c\n'
    assert [n.path for n in yp.scan(text)] == [(), ("permissions",), ("on",), ("a b",)]


def test_crlf_lone_cr_and_a_bom_read_as_lf(yp: ModuleType) -> None:
    plain = yp.scan("a: 1\nb:\n  - c\n")
    assert yp.scan(BOM + "a: 1\r\nb:\r\n  - c\r\n") == plain
    assert yp.scan("a: 1\rb:\r  - c\r") == plain
    assert yp.scan("") == yp.scan(BOM) == yp.scan("# only a comment\n") == []


def test_documents_split_on_markers_and_number_from_zero(yp: ModuleType) -> None:
    text = "%YAML 1.2\n---\na: 1\n...\n# between\n---\nb: 2\n--- |\n  text\n---\n...\nc: 3\n"
    found = [(n.doc, n.path, n.value, n.line) for n in yp.scan(text)]
    assert found == [
        (0, (), "", 3),
        (0, ("a",), "1", 3),
        (1, (), "", 7),
        (1, ("b",), "2", 7),
        (2, (), "text\n", 8),
        (3, (), "", 11),
        (4, (), "", 12),
        (4, ("c",), "3", 12),
    ]
    assert [n.doc for n in yp.scan("---\n---\n")] == [0, 1]


@pytest.mark.parametrize(
    ("text", "tag", "kind"),
    [
        ("a: !Ref Bucket", "!Ref", "plain"),
        ("a: !GetAtt Role.Arn", "!GetAtt", "plain"),
        ("a: !Sub |\n  arn:${AWS::Partition}\n", "!Sub", "literal"),
        ("a: !If [Cond, x, !Ref AWS::NoValue]", "!If", "seq"),
        ("a: !Base64 {Fn::Sub: x}", "!Base64", "map"),
        ("a: !reference [.setup, script]", "!reference", "seq"),
        ("a: !!str 1", "!!str", "plain"),
        ("a: !<tag:yaml.org,2002:str> x", "!<tag:yaml.org,2002:str>", "plain"),
        ("a: !%41b x", "!%41b", "plain"),
        ("a: !\n  x", "!", "plain"),
    ],
)
def test_tags_are_kept_as_written_on_their_node(yp: ModuleType, text: str, tag: str, kind: str) -> None:
    node = next(n for n in yp.scan(text) if n.path == ("a",))
    assert (node.tag, node.kind) == (tag, kind)


def test_tag_contents_are_read_like_any_node(yp: ModuleType) -> None:
    text = "Value: !Join\n  - ''\n  - - !Ref AWS::Region\n    - !GetAtt [Role, Arn]\n"
    assert [(n.path, n.value, n.tag) for n in yp.scan(text) if n.kind == "plain"] == [
        (("Value", 1, 0), "AWS::Region", "!Ref"),
        (("Value", 1, 1, 0), "Role", ""),
        (("Value", 1, 1, 1), "Arn", ""),
    ]


def test_anchors_aliases_and_merge_keys_are_reported_never_expanded(yp: ModuleType) -> None:
    text = "base: &b\n  perm: write\njob:\n  <<: *b\n  list: [*b, &x y]\n"
    found = [(n.path, n.value, n.kind, n.anchor) for n in yp.scan(text)]
    assert found == [
        ((), "", "map", ""),
        (("base",), "", "map", "b"),
        (("base", "perm"), "write", "plain", ""),
        (("job",), "", "map", ""),
        (("job", "<<"), "b", "alias", ""),
        (("job", "list"), "", "seq", ""),
        (("job", "list", 0), "b", "alias", ""),
        (("job", "list", 1), "y", "plain", "x"),
    ]
    found = yp.scan(text)
    assert ("job", "perm") not in {n.path for n in found}
    assert yp.MERGE == "<<"


@pytest.mark.parametrize(
    ("text", "path"),
    [
        ("jobs:\n  build:\n    <<: {permissions: write-all}\n", ("jobs", "build", "permissions")),
        ("jobs:\n  build: *tmpl\n", ("jobs", "build", "permissions")),
        ("jobs:\n  build:\n    steps: [*s]\n", ("jobs", "build")),
        ("<<: *all\nb: 1\n", ("b",)),
        ("j:\n  '<<': {p: w}\n", ("j", "p")),
        ("a:\n  <<: [*x, *y]\n", ("a",)),
    ],
)
def test_a_merge_or_alias_on_the_way_makes_a_path_unknown(yp: ModuleType, text: str, path: tuple) -> None:
    assert yp.unknown(yp.scan(text), path)


@pytest.mark.parametrize(
    ("text", "path"),
    [
        ("jobs:\n  build:\n    permissions: read\n", ("jobs", "build", "permissions")),
        ("a: *x\nb:\n  c: 1\n", ("b", "c")),
        ("a:\n  <<: *x\nb:\n  c: 1\n", ("b", "c")),
        ("a: [b, *x]\n", ("a", 0)),
    ],
)
def test_a_path_away_from_every_merge_and_alias_is_known(yp: ModuleType, text: str, path: tuple) -> None:
    assert not yp.unknown(yp.scan(text), path)


def test_properties_on_their_own_line_mark_the_node_from_there(yp: ModuleType) -> None:
    found = yp.scan("a:\n  !t\n  &x\n  b: 1\n")
    assert [(n.path, n.tag, n.anchor, n.line) for n in found][1] == (("a",), "!t", "x", 2)


def test_properties_on_their_own_line_belong_to_the_next_node(yp: ModuleType) -> None:
    found = yp.scan("a: !t\n  &x\n  k: v\nb: &y\nc: !u\n")
    assert [(n.path, n.kind, n.tag, n.anchor, n.line) for n in found] == [
        ((), "map", "", "", 1),
        (("a",), "map", "!t", "x", 1),
        (("a", "k"), "plain", "", "", 3),
        (("b",), "plain", "", "y", 4),
        (("c",), "plain", "!u", "", 5),
    ]


def test_duplicate_keys_are_all_reported(yp: ModuleType) -> None:
    assert [n.value for n in yp.scan("p: read\np: write\n") if n.path == ("p",)] == ["read", "write"]


def test_empty_values_are_empty_plain_nodes(yp: ModuleType) -> None:
    assert triples(yp, "a:\nb: # c\nc:\n-\n- x\n") == [
        ((), "", "map"),
        (("a",), "", "plain"),
        (("b",), "", "plain"),
        (("c",), "", "seq"),
        (("c", 0), "", "plain"),
        (("c", 1), "x", "plain"),
    ]


def test_the_scanner_is_stdlib_only() -> None:
    package = ROOT / "lib" / "chock_scan"
    for path in sorted(package.glob("yamlpath*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module and not n.level}
        assert {n.split(".")[0] for n in names} <= set(sys.stdlib_module_names), path.name

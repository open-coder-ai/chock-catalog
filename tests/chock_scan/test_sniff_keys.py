"""chock_scan.sniff_keys: the units (top-level key sets) and loose keys the content sniffer judges by."""

from __future__ import annotations

from types import ModuleType

import pytest

UNQUOTE = {
    "plain": ("kind", "kind"),
    "single": ("'it''s'", "it's"),
    "double": ('"a\\tb"', "a\tb"),
    "hex": ('"\\x6bind"', "kind"),
    "short-unicode": ('"\\u006bind"', "kind"),
    "long-unicode": ('"\\U0001F600"', chr(0x1F600)),
    "beyond-unicode-kept": ('"\\U99999999"', "\\U99999999"),
    "yaml-only": ('"\\N\\_\\L\\P\\e\\0"', "\x85\xa0" + chr(0x2028) + chr(0x2029) + "\x1b\0"),
    "unknown-escape-drops-backslash": ('"\\q\\/\\""', 'q/"'),
}


@pytest.mark.parametrize(("token", "value"), UNQUOTE.values(), ids=UNQUOTE.keys())
def test_unquote(sk: ModuleType, token: str, value: str) -> None:
    assert sk.unquote(token) == value


def test_units_of_yaml_documents_and_sequences(sk: ModuleType) -> None:
    text = "a: 1\nb:\n  c: 2\n---\n- d: 1\n  e: 2\n- f: 3\n"
    assert sk.units(text) == [
        sk.Unit(frozenset({"a", "b"}), 0),
        sk.Unit(frozenset({"d", "e"}), 0),
        sk.Unit(frozenset({"f"}), 0),
    ]


def test_units_of_json(sk: ModuleType) -> None:
    assert sk.units('{"a": 1, "b": {"c": 2}}') == [sk.Unit(frozenset({"a", "b"}), 0)]
    assert sk.units('[{"a": 1}, 2, {"b": 3}]') == [sk.Unit(frozenset({"a"}), 0), sk.Unit(frozenset({"b"}), 0)]
    assert sk.units('{"a": 1} trailing') == [sk.Unit(frozenset({"a"}), 0)]
    assert sk.units("[1, 2]") == []
    assert sk.units("[1e999, {}]") == [sk.Unit(frozenset(), 0)]
    not_json = [sk.Unit(frozenset(), 0)]  # read as YAML: one root line that names no key
    assert sk.units('"just a string"') == not_json
    assert sk.units("{" * 100_000) == not_json
    assert sk.units("[" + "1" * 5000 + "]") == not_json


def test_opaque_keys_are_counted(sk: ModuleType) -> None:
    assert sk.units("? [a, b]\n: 1\n*x : 2\nc: 3\n") == [sk.Unit(frozenset({"c"}), 2)]


def test_an_anchor_is_seen_only_after_it_is_set(sk: ModuleType) -> None:
    assert sk.units("*k : 1\nx: &k kind\n*k : 2\n") == [sk.Unit(frozenset({"x", "kind"}), 1)]


def test_anchors_do_not_cross_documents(sk: ModuleType) -> None:
    assert sk.units("x: &k kind\n---\n*k : 2\n") == [sk.Unit(frozenset({"x"}), 0), sk.Unit(frozenset(), 1)]


def test_loose_keys(sk: ModuleType) -> None:
    text = 'a: 1\n  "b": 2\n# c: 3\n{d: 4, "e":5, [f: 6]}\nx:y\n  - g : 7\n'
    assert sk.loose_keys(text) == {"a", "b", "d", "e", "f", "x", "g"}

"""scan-secrets-entropy: the dotted-name shape reads arrowed names the same, in time linear in the value."""

from __future__ import annotations

import importlib.util
import itertools
import time

import pytest
from trees import ROOT

SPEC = importlib.util.spec_from_file_location(
    "entropy_shapes_under_test",
    ROOT / "base" / "scan-secrets-entropy" / "implementations" / "entropyscan" / "shapes.py",
)
assert SPEC is not None
assert SPEC.loader is not None
shapes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shapes)
OLD = r"[\w$-]*"
ALPHABET = "a-_>$.1"


def test_the_name_segments_cannot_swallow_the_arrow_that_follows_them() -> None:
    assert OLD not in shapes._CODE.pattern
    assert shapes._CODE.pattern.count("(?:-(?!>)|[\\w$])*") == 2


@pytest.mark.parametrize(
    "value", ["a->b", "a-b->c", "a-->b", "a.b-c.d", "$a-b->$c_d", "a-b(c-d)", "a-b-", "a->", "->a", "a>b"]
)
def test_it_matches_what_the_plain_class_matched(value: str) -> None:
    plain = shapes.re.compile(shapes._CODE.pattern.replace("(?:-(?!>)|[\\w$])*", OLD))
    assert bool(shapes._CODE.fullmatch(value)) == bool(plain.fullmatch(value))


def test_it_agrees_with_the_plain_class_on_every_short_string() -> None:
    plain = shapes.re.compile(shapes._CODE.pattern.replace("(?:-(?!>)|[\\w$])*", OLD))
    for size in range(1, 8):
        for chars in itertools.product(ALPHABET, repeat=size):
            value = "".join(chars)
            assert bool(shapes._CODE.fullmatch(value)) == bool(plain.fullmatch(value)), value


@pytest.mark.parametrize(
    "make", [lambda n: "a" + "-" * n + "!", lambda n: "a" + "->a" * n + "!", lambda n: "a" + "-" * n + "->"]
)
def test_matching_time_grows_linearly(make) -> None:
    def took(n: int) -> float:
        start = time.perf_counter()
        shapes._CODE.fullmatch(make(n))
        return time.perf_counter() - start

    assert took(40_000) < 1.0

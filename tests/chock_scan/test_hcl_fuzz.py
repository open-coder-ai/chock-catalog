"""Seeded property, mutation and timing tests for chock_scan.hcl and hcl_json (hypothesis is not a dev dependency here).

Round trips: random valid HCL (hostile comments, CRLF, BOM, heredocs, escapes) must read back exactly the
model it was rendered from -- every key, label, literal and line -- so nothing a comment, string or
heredoc holds becomes a key, and no key goes missing. Mutations of real files and random text must give a
result or HclError, nothing else, within a time bound. A failure reproduces from its seed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from types import SimpleNamespace

import pytest
from chock_scan.hclgen import REF, document
from chock_scan.hclgen_json import json_document
from chock_scan.hclload import CORPUS, rng

SEEDS = range(300)
MUTATION_SEEDS = range(60)
SOUP = list("{}[]()\"'#/*<-$%\\\n\r\t=,:.? abcEOT0123456789~!&|\u2003\ufeff\u00e9")
NATIVE = sorted(p for p in CORPUS.rglob("*") if p.suffix in (".tf", ".hcl") and "invalid" not in p.parts)


def want(m: SimpleNamespace, value: object) -> object:
    """A model value with COMPUTED where the model says REF."""
    if value is REF:
        return m.hcl.COMPUTED
    if isinstance(value, tuple):
        return tuple(want(m, v) for v in value)
    if isinstance(value, dict):
        return {k: want(m, v) for k, v in value.items()}
    return value


def check(m: SimpleNamespace, block: object, model: dict) -> None:
    got = [(a.key, a.value, a.line) for a in block.attributes]
    assert got == [(key, want(m, value), line) for key, (value, line) in model["attrs"].items()]
    assert len(block.blocks) == len(model["blocks"])
    for child, (kind, labels, line, inner) in zip(block.blocks, model["blocks"], strict=True):
        assert (child.type, child.labels, child.line) == (kind, labels, line)
        check(m, child, inner)


@pytest.mark.parametrize("seed", SEEDS)
def test_random_valid_hcl_reads_back_exactly(m: SimpleNamespace, seed: int) -> None:
    src, model = document(seed)
    check(m, m.hcl.parse(src), model)


@pytest.mark.parametrize("seed", SEEDS)
def test_random_terraform_json_reads_back_exactly(m: SimpleNamespace, seed: int) -> None:
    src, model = json_document(seed)
    root = m.hcl_json.parse_json(src)
    got = {}
    for block in root.blocks:
        assert block.type == "resource"
        nested = [(b.type, {a.key: a.value for a in b.attributes}) for b in block.blocks]
        got[block.labels] = ({a.key: a.value for a in block.attributes}, nested)
    assert got == {labels: (want(m, attrs), want(m, nested)) for labels, (attrs, nested) in model.items()}
    assert len(root.blocks) == len(model)


def _mutate(text: str, seed: int) -> str:
    r = rng(seed)
    chars = list(text)
    for _ in range(r.randrange(1, 6)):
        at = r.randrange(len(chars) + 1)
        pick = r.randrange(3)
        if pick == 0:
            chars[at:at] = r.choices(SOUP, k=r.randrange(1, 4))
        elif pick == 1:
            del chars[at : at + r.randrange(1, 20)]
        else:
            chars[at:at] = chars[r.randrange(len(chars) + 1) :][: r.randrange(1, 40)]
    return "".join(chars)


def _parse_or_refuse(m: SimpleNamespace, text: str, *, as_json: bool = False) -> None:
    started = time.perf_counter()
    try:
        root = m.hcl_json.parse_json(text) if as_json else m.hcl.parse(text)
    except m.hcl.HclError as exc:
        assert exc.line >= 1
    else:
        lines = text.count("\n") + 1
        for block in [root, *m.hcl.walk(root)]:
            assert 1 <= block.line <= lines
            for attr in block.attributes:
                assert 1 <= attr.line <= lines
                assert attr.expr in text
    assert time.perf_counter() - started < 2


@pytest.mark.parametrize("seed", MUTATION_SEEDS)
def test_a_mutated_real_file_parses_or_raises_hclerror(m: SimpleNamespace, seed: int) -> None:
    path = NATIVE[seed % len(NATIVE)]
    _parse_or_refuse(m, _mutate(path.read_text(encoding="utf-8"), seed))


@pytest.mark.parametrize("seed", MUTATION_SEEDS)
def test_mutated_terraform_json_parses_or_raises_hclerror(m: SimpleNamespace, seed: int) -> None:
    src, _ = json_document(seed)
    _parse_or_refuse(m, _mutate(src, seed), as_json=True)


@pytest.mark.parametrize("seed", SEEDS)
def test_random_text_parses_or_raises_hclerror(m: SimpleNamespace, seed: int) -> None:
    r = rng(seed)
    text = "".join(r.choices(SOUP, k=r.randrange(0, 200)))
    _parse_or_refuse(m, text)
    _parse_or_refuse(m, text, as_json=True)


N = 1 << 16
Build = Callable[[int], str]
#: name -> (the text at size n, the HclError message it must raise, or None when it must parse).
PATHOLOGICAL: dict[str, tuple[Build, str | None]] = {
    "open-brackets": (lambda n: "x = " + "[" * n, "brackets nested deeper than 64"),
    "commas": (lambda n: "x = [" + "," * n + "]", None),
    "empty-strings": (lambda n: "x = [" + '"",' * (n // 3) + "]", None),
    "templates": (lambda n: 'x = "' + '${"a"}' * (n // 6) + '"', None),
    "heredoc-lines": (lambda n: "x = <<E\n" + "a\n" * (n // 2) + "E\n", None),
    "unclosed-heredoc": (lambda n: "x = <<E\n" + "E \u2003x\n" * (n // 5), "heredoc E is never closed"),
    "unclosed-comment": (lambda n: "/*" + "*" * n, "unterminated /\\* comment"),
    "attributes": (lambda n: "".join(f"a{i} = 1\n" for i in range(n // 10)), None),
    "empty-blocks": (lambda n: "b {\n}\n" * (n // 6), None),
    "computed-keys": (lambda n: "x = [" + "{(k) = 1}," * (n // 10) + "]", None),
    "computed-elements": (lambda n: "x = [" + "a.b," * (n // 4) + "]", None),
    "newlines": (lambda n: "\n" * n, None),
    "crlf": (lambda n: "a = 1\r\n" + "\r\n" * n, None),
    "identifiers": (lambda n: "a " * (n // 2), "block a: expected a label"),
    "unicode-identifiers": (lambda n: "\u00e9" * n, "block"),
}
JSON_PATHOLOGICAL: dict[str, tuple[Build, str | None]] = {
    "zeros": (lambda n: '{"locals": {"a": [' + "0," * (n // 2) + "0]}}", None),
    "objects": (lambda n: '{"locals": {"a": [' + "{}," * (n // 3) + "{}]}}", None),
    "keys": (lambda n: '{"locals": {' + ",".join(f'"k{i}": 1' for i in range(n // 12)) + "}}", None),
    "deep": (lambda n: '{"locals": {"a": ' + "[" * n + "]" * n + "}}", "nested"),
    "templates": (lambda n: '{"locals": {"a": "' + "${x}" * (n // 4) + '"}}', None),
    "deep-and-wide": (
        lambda n: '{"resource":{"a":{"b":' + '{"x":' * 55 + "[" + '"${x}yy",' * (n // 9) + '""]' + "}" * 58,
        None,
    ),
    "array-bodies": (
        lambda n: '{"resource":{"t":{"n":[[' + ",".join(f'{{"k{i}":1}}' for i in range(n // 10)) + "]]}}}",
        None,
    ),
}


def _outcome(m: SimpleNamespace, parse: Callable[[str], object], text: str, error: str | None) -> float:
    """Seconds to parse `text`, asserting the outcome: that HclError (matching `error`), or a result."""
    started = time.perf_counter()
    if error is None:
        assert parse(text) is not None
    else:
        with pytest.raises(m.hcl.HclError, match=error):
            parse(text)
    return time.perf_counter() - started


def _linear(m: SimpleNamespace, parse: Callable[[str], object], build: Build, error: str | None) -> None:
    """At size N within 5s, and 8x the text within 20x the time (quadratic work would take 64x)."""
    big = min(_outcome(m, parse, build(N), error) for _ in range(2))
    small = min(_outcome(m, parse, build(N // 8), error) for _ in range(3))
    assert big < 5
    assert big < 20 * small + 0.05, (small, big)


@pytest.mark.parametrize("name", PATHOLOGICAL)
def test_pathological_text_is_linear_and_explicit(m: SimpleNamespace, name: str) -> None:
    _linear(m, m.hcl.parse, *PATHOLOGICAL[name])


@pytest.mark.parametrize("name", JSON_PATHOLOGICAL)
def test_pathological_json_is_linear_and_explicit(m: SimpleNamespace, name: str) -> None:
    _linear(m, m.hcl_json.parse_json, *JSON_PATHOLOGICAL[name])


def test_a_chain_of_misshapen_labelled_blocks_is_read_once(m: SimpleNamespace) -> None:
    """Each `dynamic` below has a key that is not a label, so it falls back to no labels: once, not 2^depth times."""
    src = '{"resource":{"t":{"n":' + '{"dynamic":{"a":' * 28 + '{"k":1}' + ',"x":1}}' * 28 + "}}}"
    started = time.perf_counter()
    root = m.hcl_json.parse_json(src)
    assert time.perf_counter() - started < 1
    depth = sum(1 for b in m.hcl.walk(root) if b.type == "dynamic")
    assert depth == 28


def test_json_time_does_not_grow_with_depth(m: SimpleNamespace) -> None:
    """The same 64 KiB of templates nested 55 deep costs about what it does at depth 1 (it once cost size x depth)."""

    def at(depth: int) -> str:
        head = '{"resource":{"a":{"b":' + '{"x":' * depth
        return head + "[" + '"${x}yy",' * (N // 9) + '""]' + "}" * (depth + 3)

    shallow = min(_outcome(m, m.hcl_json.parse_json, at(1), None) for _ in range(2))
    deep = min(_outcome(m, m.hcl_json.parse_json, at(55), None) for _ in range(2))
    assert deep < 3 * shallow + 0.05, (shallow, deep)

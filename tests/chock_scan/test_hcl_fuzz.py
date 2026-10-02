"""Seeded property, mutation and timing tests for chock_scan.hcl and hcl_json (hypothesis is not a dev dependency here).

Round trips: random valid HCL (hostile comments, CRLF, BOM, heredocs, escapes) must read back exactly the
model it was rendered from -- every key, label, literal and line -- so nothing a comment, string or
heredoc holds becomes a key, and no key goes missing. Mutations of real files and random text must give a
result or HclError, nothing else, within a time bound. A failure reproduces from its seed.
"""

from __future__ import annotations

import contextlib
import time
from types import SimpleNamespace

import pytest
from chock_scan.hclgen import REF, document, json_document
from chock_scan.hclload import CORPUS, rng

SEEDS = range(300)
MUTATION_SEEDS = range(60)
SOUP = list("{}[]()\"'#/*<-$%\\\n\r\t=,:.? abcEOT0123456789~!&|\u2003\ufeff\u00e9")
NATIVE = sorted(p for p in CORPUS.rglob("*") if p.suffix in (".tf", ".hcl") and "invalid" not in p.parts)


def check(m: SimpleNamespace, block: object, model: dict) -> None:
    got = [(a.key, a.value, a.line) for a in block.attributes]
    assert got == [(key, value, line) for key, (value, line) in model["attrs"].items()]
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
    want = [
        ("resource", (kind, name), {k: m.hcl.COMPUTED if v is REF else v for k, v in attrs.items()})
        for kind, bodies in model.items()
        for name, attrs in bodies.items()
    ]
    assert [(b.type, b.labels, {a.key: a.value for a in b.attributes}) for b in root.blocks] == want
    assert all(b.blocks == () for b in root.blocks)


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
PATHOLOGICAL = {
    "open-brackets": "x = " + "[" * N,
    "commas": "x = [" + "," * N + "]",
    "empty-strings": "x = [" + '"",' * (N // 3) + "]",
    "templates": 'x = "' + '${"a"}' * (N // 6) + '"',
    "heredoc-lines": "x = <<E\n" + "a\n" * (N // 2) + "E\n",
    "unclosed-heredoc": "x = <<E\n" + "E \u2003x\n" * (N // 5),
    "unclosed-comment": "/*" + "*" * N,
    "attributes": "".join(f"a{i} = 1\n" for i in range(N // 10)),
    "empty-blocks": "b {\n}\n" * (N // 6),
    "computed-keys": "x = [" + "{(k) = 1}," * (N // 10) + "]",
    "nested-objects": "x = " + "{a = " * 64 + "1" + "}" * 64 + "\n" + "y = " + "{a = " * 63 + "{(k) = 1}" + "}" * 63,
    "newlines": "\n" * N,
    "crlf": "a = 1\r\n" + "\r\n" * N,
    "identifiers": "a " * (N // 2),
    "unicode-identifiers": "\u00e9" * N,
}


@pytest.mark.parametrize("name", PATHOLOGICAL)
def test_pathological_text_is_linear_and_explicit(m: SimpleNamespace, name: str) -> None:
    started = time.perf_counter()
    with contextlib.suppress(m.hcl.HclError):
        m.hcl.parse(PATHOLOGICAL[name])
    assert time.perf_counter() - started < 5


JSON_PATHOLOGICAL = {
    "zeros": '{"locals": {"a": [' + "0," * (N // 2) + "0]}}",
    "objects": '{"locals": {"a": [' + "{}," * (N // 3) + "{}]}}",
    "keys": '{"locals": {' + ",".join(f'"k{i}": 1' for i in range(N // 12)) + "}}",
    "deep": '{"locals": {"a": ' + "[" * N + "]" * N + "}}",
    "templates": '{"locals": {"a": "' + "${x}" * (N // 4) + '"}}',
}


@pytest.mark.parametrize("name", JSON_PATHOLOGICAL)
def test_pathological_json_is_linear_and_explicit(m: SimpleNamespace, name: str) -> None:
    started = time.perf_counter()
    with contextlib.suppress(m.hcl.HclError):
        m.hcl_json.parse_json(JSON_PATHOLOGICAL[name])
    assert time.perf_counter() - started < 5

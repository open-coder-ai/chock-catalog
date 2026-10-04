"""chock_scan.jsonc against generated documents, arbitrary text and hostile input.

Property cases draw from a seeded generator (hypothesis is not a dev dependency here), so a failure
reproduces from its seed. Each generated document is built as a list of key/value pairs, which is
the reference model the duplicate report and the last-wins value are checked against.
"""

from __future__ import annotations

import contextlib
import json
import random
from pathlib import Path
from types import ModuleType

import pytest
import untraced

SEEDS = range(60)
TRIVIA = ["", " ", "\n", "\r\n", "\t", "// c /* x\n", "//\r\n", "/**/", "/* // \n * */", '/*"*/', '// "\n']
TEXT = ["//", "/*", "*/", '"', "\\", ",", "]", "}", "\u2028", "\u00e9", "\U0001f600", "a", " ", "\t"]


def _rng(seed: int) -> random.Random:
    return random.Random(seed)  # noqa: S311 -- reproducible test data, not a secret


def _model(rng: random.Random, depth: int = 0) -> object:
    """A JSON value; an object is ("obj", [(key, model), ...]) so a key may repeat."""
    pick = rng.randrange(8 if depth < 4 else 5)
    if pick == 0:
        return rng.choice([None, True, False])
    if pick == 1:
        return rng.choice([0, -1, 10**20, rng.randrange(-1000, 1000), 0.5, -2.5e-3])
    if pick in {2, 3, 4}:
        return "".join(rng.choice(TEXT) for _ in range(rng.randrange(0, 6)))
    if pick == 5:
        return [_model(rng, depth + 1) for _ in range(rng.randrange(0, 4))]
    keys = ["a", "b", "//", "/*", "e"]
    return ("obj", [(rng.choice(keys), _model(rng, depth + 1)) for _ in range(rng.randrange(0, 5))])


def _value(model: object) -> object:
    """What a last-wins loader returns for the model."""
    if isinstance(model, tuple):
        return {key: _value(val) for key, val in model[1]}
    if isinstance(model, list):
        return [_value(v) for v in model]
    return model


def _duplicates(model: object, path: tuple[str | int, ...] = ()) -> list[tuple[tuple[str | int, ...], tuple]]:
    """Each repeated key with every value, in order of first appearance, then what is under every value."""
    out: list[tuple[tuple[str | int, ...], tuple]] = []
    if isinstance(model, list):
        for i, val in enumerate(model):
            out += _duplicates(val, (*path, i))
    elif isinstance(model, tuple):
        groups: dict[str, list[object]] = {}
        for key, val in model[1]:
            groups.setdefault(key, []).append(val)
        for key, vals in groups.items():
            if len(vals) > 1:
                out.append(((*path, key), tuple(_value(v) for v in vals)))
            for val in vals:
                out += _duplicates(val, (*path, key))
    return out


def _render(rng: random.Random, model: object) -> str:
    """JSONC for the model: trivia between every token, a trailing comma sometimes, strings escaped or not."""

    def gap() -> str:
        return rng.choice(TRIVIA)

    def items(parts: list[str], open_: str, close: str) -> str:
        tail = "," + gap() if parts and rng.random() < 0.4 else ""
        return open_ + gap() + ("," + gap()).join(parts) + tail + close

    if isinstance(model, tuple):
        pairs = [f"{_key(rng, k)}{gap()}:{gap()}{_render(rng, v)}" for k, v in model[1]]
        return items(pairs, "{", "}")
    if isinstance(model, list):
        return items([_render(rng, v) for v in model], "[", "]")
    return json.dumps(model, ensure_ascii=rng.random() < 0.5)


def _key(rng: random.Random, key: str) -> str:
    """The key as JSON, sometimes with one character spelled as a \\u escape: still the same key."""
    if key and rng.random() < 0.3:
        at = rng.randrange(len(key))
        return json.dumps(key[:at])[:-1] + f"\\u{ord(key[at]):04x}" + json.dumps(key[at + 1 :])[1:]
    return json.dumps(key, ensure_ascii=rng.random() < 0.5)


@pytest.mark.parametrize("seed", SEEDS)
def test_a_generated_document_loads_to_its_model(jsonc: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    model = _model(rng)
    text = rng.choice(["", "\ufeff"]) + rng.choice(TRIVIA) + _render(rng, model) + rng.choice(TRIVIA)
    doc = jsonc.loads(text)
    assert doc.value == _value(model)
    assert [(d.path, d.values) for d in doc.duplicates] == _duplicates(model)


@pytest.mark.parametrize("seed", SEEDS)
def test_strip_keeps_length_line_breaks_and_strings(jsonc: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    text = _render(rng, _model(rng))
    clean = jsonc.strip(text)
    assert len(clean) == len(text)
    assert [i for i, c in enumerate(clean) if c in "\r\n"] == [i for i, c in enumerate(text) if c in "\r\n"]
    assert all(a in {b, " "} for a, b in zip(clean, text, strict=True))
    assert json.loads(clean) == jsonc.loads(text).value


@pytest.mark.parametrize("seed", SEEDS)
def test_strict_json_is_read_exactly_as_json_reads_it(jsonc: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    value = _value(_model(rng))
    text = json.dumps(value, indent=rng.choice([None, 2]), ensure_ascii=rng.random() < 0.5)
    assert jsonc.strip(text) == text
    assert jsonc.loads(text) == (json.loads(text), ())


@pytest.mark.parametrize("seed", SEEDS)
def test_arbitrary_text_loads_or_raises_jsonc_error_only(jsonc: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    alphabet = '{}[],:"\\/*\n\r\t 01-.eEtrufalsn\u2028\ufeff\u00a0x'
    for _ in range(50):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 40)))
        try:
            clean = jsonc.strip(text)
        except jsonc.JsoncError as exc:
            assert exc.pos is None or 0 <= exc.pos <= len(text)
        else:
            assert len(clean) == len(text)
        try:
            jsonc.loads(text)
        except jsonc.JsoncError as exc:
            assert exc.pos is None or (exc.line >= 1 and exc.col >= 1)


@pytest.mark.parametrize("seed", SEEDS)
def test_a_mutated_document_loads_or_raises_jsonc_error_only(jsonc: ModuleType, seed: int) -> None:
    rng = _rng(seed)
    chars = list(_render(rng, _model(rng)))
    for _ in range(rng.randrange(1, 4)):
        at = rng.randrange(0, len(chars) + 1)
        chars[at : at + rng.randrange(0, 2)] = rng.choice(['"', "/", "*", ",", "\\", "\r", "]", "{", "//", "/*"])
    try:
        doc = jsonc.loads("".join(chars))
    except jsonc.JsoncError:
        return
    assert isinstance(doc.duplicates, tuple)


HOSTILE = {
    "openers": lambda n: "[" * n,
    "open-string": lambda n: '"' + "\\\\" * (n // 2 - 1),
    "escaped-quotes": lambda n: '["' + '\\"' * (n // 2 - 2) + '"]',
    "block-starts": lambda n: "/*" * (n // 2),
    "slashes": lambda n: "/" * n,
    "commas": lambda n: "[" + "," * (n - 2) + "]",
    "values": lambda n: "[" + "1," * (n // 2 - 2) + "1]",
    "line-comment": lambda n: "[1]//" + "x" * (n - 5),
    "many-duplicates": lambda n: "{" + '"a":1,' * (n // 6 - 1) + '"a":1}',
    "nested-duplicates": lambda n: '{"a":' * 250 + "1" + ',"a":1}' * 250 + " " * (n - 3001),
    "quotes": lambda n: '"' * n,
}


CHILD = """
import contextlib, json, sys, time
from pathlib import Path
from chock_scan.conftest import load
from chock_scan.test_jsonc_fuzz import HOSTILE
jsonc = load(Path(sys.argv[1]), "jsonc")
text = HOSTILE[sys.argv[2]](jsonc.LIMIT)
start = time.perf_counter()
with contextlib.suppress(jsonc.JsoncError):
    jsonc.loads(text)
print(json.dumps([time.perf_counter() - start]))
"""


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_input_at_the_size_limit_finishes_quickly(jsonc: ModuleType, name: str) -> None:
    """Timed in a child outside the coverage tracer; this process reads the input too, so its lines stay covered."""
    text = HOSTILE[name](jsonc.LIMIT)
    assert len(text) <= jsonc.LIMIT
    with contextlib.suppress(jsonc.JsoncError):
        jsonc.loads(text)
    (seconds,) = untraced.run(CHILD, str(Path(jsonc.__file__).parent), name)
    assert seconds < 5

"""chock_scan.yamlpath against PyYAML: real files, generated documents, mutations, and hostile sizes.

PyYAML's event stream is the reference (yamloracle). Where both read a text they must report the same
nodes -- path, value, line, style, tag, anchor, document -- or the scanner could show a gate a different
file than the one a loader acts on. Where only the scanner refuses, it must refuse with ParseError.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import ModuleType

import pytest
from chock_scan import yamlgen, yamloracle
from trees import ROOT

CORPUS = Path(__file__).parent / "corpus"
VENDORED = sorted(p for p in (CORPUS / "vendor").rglob("*.y*ml"))
SKIP_DIRS = {".git", ".framework", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv", "node_modules"}
OWN = sorted(p for p in ROOT.rglob("*.y*ml") if p.is_file() and not set(p.relative_to(ROOT).parts) & SKIP_DIRS)
SIZE = 1 << 18
SECONDS = 15.0


def reference(text: str) -> list[tuple] | None:
    """PyYAML's nodes, or None when PyYAML cannot read the text."""
    try:
        return [tuple(node) for node in yamloracle.nodes(text)]
    except Exception:  # noqa: BLE001 -- any PyYAML failure (it raises ValueError and others too) is "unreadable"
        return None


def scanned(yp: ModuleType, text: str) -> list[tuple] | None:
    try:
        return [tuple(node) for node in yp.scan(text)]
    except yp.ParseError:
        return None


@pytest.mark.parametrize("path", VENDORED, ids=[p.relative_to(CORPUS).as_posix() for p in VENDORED])
def test_each_vendored_file_reads_as_pyyaml_reads_it(yp: ModuleType, path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    found = yp.scan(text)
    assert len(found) > 1
    assert [tuple(n) for n in found] == reference(text)
    assert yp.scan(chr(0xFEFF) + text.replace("\n", "\r\n")) == found


def test_every_yaml_file_in_this_repository_reads_as_pyyaml_reads_it(yp: ModuleType) -> None:
    assert len(OWN) > 100
    differ = [p.relative_to(ROOT).as_posix() for p in OWN if scanned(yp, t := p.read_text("utf-8-sig")) != reference(t)]
    assert not differ


def test_every_vendored_file_has_its_source_and_licence_recorded() -> None:
    sources = (CORPUS / "SOURCES.md").read_text(encoding="utf-8")
    for path in VENDORED:
        assert f"`{path.relative_to(CORPUS / 'vendor').as_posix()}`" in sources, path
    licences = {p.name for p in (CORPUS / "vendor" / "LICENSES").iterdir()}
    assert licences == {name for name in licences if f"`{name}`" in sources}
    assert len(licences) == 7


@pytest.mark.parametrize("block", range(8))
def test_generated_documents_read_as_pyyaml_reads_them(yp: ModuleType, block: int) -> None:
    for seed in range(block * 60, block * 60 + 60):
        text = yamlgen.document(yamlgen.rng(seed))
        assert scanned(yp, text) == reference(text), f"seed {seed}: {text!r}"


@pytest.mark.parametrize("block", range(10))
def test_mutated_documents_are_refused_or_read_as_pyyaml_reads_them(yp: ModuleType, block: int) -> None:
    """Never another exception, and never a different reading of a text both can read."""
    read = 0
    for seed in range(block * 150, block * 150 + 150):
        r = yamlgen.rng(seed)
        text = yamlgen.mutate(r, yamlgen.document(r))
        mine, theirs = scanned(yp, text), reference(text)
        if mine is not None and theirs is not None:
            assert mine == theirs, f"seed {seed}: {text!r}"
            read += 1
    assert read > 30


def _hostile() -> dict[str, str]:
    """Inputs built to find quadratic work: long runs, deep folds, many breaks, many escapes."""
    n = SIZE
    return {
        "keys": "".join(f"k{i}: v{i}\n" for i in range(n // 14)),
        "sequence": "- x\n" * (n // 4),
        "flow": "[" + "a, " * (n // 3 - 2) + "a]",
        "blanks before a comment": "a: b" + " " * (n - 10) + "#c",
        "blanks inside a plain scalar": "a: b" + " " * (n - 10) + "x",
        "tabs before a break": "a: b" + "\t" * (n - 10),
        "folded plain lines": "a: b\n" + "  c\n" * (n // 4 - 2),
        "blank lines in a plain scalar": "a: b\n" + "\n" * (n - 10) + "  c",
        "double-quoted escapes": 'a: "' + "\\t" * (n // 2 - 4) + '"',
        "single-quoted quotes": "a: '" + "''" * (n // 2 - 4) + "'",
        "quoted breaks": 'a: "' + " \n" * (n // 2 - 4) + '"',
        "literal block": "a: |\n" + "  x\n" * (n // 4 - 2),
        "folded block": "a: >\n" + "  x\n\n" * (n // 5 - 2),
        "colons": "a: " + "b:" * (n // 2 - 4),
        "unterminated quote": 'a: "' + "x" * (n - 10),
        "unterminated flow": "a: [" + "x, " * (n // 3 - 4),
        "documents": "---\na: 1\n" * (n // 9),
        "aliases": "".join(f"- &a{i} x\n- *a{i}\n" for i in range(n // 24)),
        "comment lines": "a:\n" + "# c\n" * (n // 4 - 4) + "  b: 1",
        "tags": "- !t x\n" * (n // 7),
        "deep flow": "[" * (n // 2) + "]" * (n // 2),
        "deep block": "".join(" " * i + "- " for i in range(0, 1000, 2)),
    }


@pytest.mark.parametrize(("name", "text"), list(_hostile().items()), ids=list(_hostile()))
def test_hostile_input_is_read_or_refused_in_linear_time(yp: ModuleType, name: str, text: str) -> None:
    assert len(text) <= SIZE, name
    start = time.perf_counter()
    scanned(yp, text)
    assert time.perf_counter() - start < SECONDS

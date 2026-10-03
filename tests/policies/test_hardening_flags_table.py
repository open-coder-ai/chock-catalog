"""hardening-flags: the data table's checks and the section and hit helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from policies import hardflagskit

mod = hardflagskit.load_gate()
ENTRIES = mod.rules.load()


def table(tmp_path: Path, entries: object) -> Path:
    path = tmp_path / "data" / "flags.json"
    path.parent.mkdir()
    doc = {
        "schema": 1,
        "kind": "curated",
        "as_of": "2026-10-02",
        "source": "https://example.invalid/x",
        "entries": entries,
    }
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


GOOD = {"id": "a-flag", "tier": "block", "langs": ["c"], "pattern": "-x", "what": "turns x off"}


@pytest.mark.parametrize(
    ("entries", "problem"),
    [
        ([], "non-empty list"),
        ("nope", "non-empty list"),
        ([5], "fields must be"),
        ([{**GOOD, "extra": 1}], "fields must be"),
        ([{k: v for k, v in GOOD.items() if k != "what"}], "fields must be"),
        ([{**GOOD, "id": "Bad_Id"}], "unique kebab-case"),
        ([{**GOOD, "id": 7}], "unique kebab-case"),
        ([GOOD, GOOD], "unique kebab-case"),
        ([{**GOOD, "tier": "warn"}], "tier must be"),
        ([{**GOOD, "langs": []}], "langs must be"),
        ([{**GOOD, "langs": ["cobol"]}], "langs must be"),
        ([{**GOOD, "langs": "c"}], "langs must be"),
        ([{**GOOD, "what": " "}], "what must say"),
        ([{**GOOD, "what": 3}], "what must say"),
        ([{**GOOD, "pattern": "("}], "does not compile"),
        ([{**GOOD, "pattern": 5}], "does not compile"),
        ([{**GOOD, "pattern": "x*"}], "empty string"),
        ([{**GOOD, "section": "["}], "does not compile"),
        ([{**GOOD, "section": "^$"}], "empty string"),
        ([GOOD], "required entries missing"),
    ],
)
def test_a_bad_table_is_refused(tmp_path: Path, entries: object, problem: str) -> None:
    with pytest.raises(mod.TableError, match=problem):
        mod.rules.load(table(tmp_path, entries))


def test_a_good_table_loads_with_a_section(tmp_path: Path) -> None:
    rows = [{**GOOD, "id": name} for name in sorted(mod.rules.REQUIRED)]
    loaded = mod.rules.load(table(tmp_path, [*rows, {**GOOD, "section": "^profile$"}]))
    assert [(e.id, e.tier, bool(e.section)) for e in loaded][-1] == ("a-flag", "block", True)


def test_sections_and_hits() -> None:
    assert mod.rules.section_of("[profile.release]", "x") == "profile.release"
    assert mod.rules.section_of('[[bin."a b"]]', "x") == "bin.ab"
    assert mod.rules.section_of("name = 1", "x") == "x"
    assert mod.rules.section_of('["a", "b"]', "x") == "x"
    assert mod.rules.section_of("  [profile.dev]  ", "x") == "profile.dev"
    entry = ENTRIES[0]
    assert list(mod.rules.hits(ENTRIES, frozenset({"kernel"}), "-fno-stack-protector", "")) == []
    assert [e.id for e, _ in mod.rules.hits(ENTRIES, frozenset({"c"}), "-fno-stack-protector", "")] == [entry.id]

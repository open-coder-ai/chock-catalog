"""tools/check_data_tables.py: D7 freshness over every data table, on an injected date and on the real one."""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import check_data_tables as cdt
import pytest
from trees import ROOT

DAY = dt.date(2026, 3, 1)


def _table(**overrides: object) -> dict:
    doc = {"schema": 1, "kind": "ioc", "as_of": "2026-02-01", "source": "https://example.org", "entries": []}
    return doc | overrides


def _put(root: Path, rel: str, doc: object) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return path


@pytest.fixture
def cat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A catalog with one policy and no legacy tables."""
    (tmp_path / "base" / "p").mkdir(parents=True)
    monkeypatch.setattr(cdt, "LEGACY", {})
    return tmp_path


def test_the_real_tables_are_fresh_today() -> None:
    """The one check on the real date: CI fails the day a table passes its kind's limit."""
    assert cdt.main([], ROOT) == 0


def test_every_legacy_entry_exists_and_is_rule_configuration_without_an_envelope() -> None:
    found = {p.relative_to(ROOT).as_posix() for p in cdt.tables(ROOT)}
    assert set(cdt.LEGACY) <= found
    assert all(reason.endswith("(pre-D7)") for reason in cdt.LEGACY.values())
    assert all(cdt._legacy(ROOT / rel) == [] for rel in cdt.LEGACY)


def test_tables_are_found_at_the_root_and_at_any_depth_in_a_policy_whatever_the_case(cat: Path) -> None:
    for rel in ("Data/a.json", "base/p/implementations/data/b.json", "base/p/x/y/DATA/c.JSON"):
        _put(cat, rel, _table())
    for rel in ("data/sub/d.json", "base/p/data.json", "base/p/implementations/data/e.yaml", "tests/data/f.json"):
        _put(cat, rel, "{}")
    assert sorted(p.name for p in cdt.tables(cat)) == ["a.json", "b.json", "c.JSON", "d.json"]


def test_fresh_tables_pass_and_the_count_is_printed(cat: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _put(cat, "data/a.json", _table())
    _put(cat, "base/p/implementations/data/b.json", _table(kind="top-n", as_of="2025-03-02"))
    assert cdt.main(["--today", "2026-03-01"], cat) == 0
    assert capsys.readouterr().out == "data tables: 2 checked, fresh on 2026-03-01\n"


@pytest.mark.parametrize(
    ("doc", "today", "problem"),
    [
        (_table(as_of="2025-11-01"), DAY, "data/a.json: as_of 2025-11-01 is 120 days old; a ioc table must be"),
        (_table(as_of="2026-03-02"), DAY, "data/a.json: as_of 2026-03-02 is after today (2026-03-01)"),
        (_table(kind="top-n", as_of="2025-03-01"), DAY, "data/a.json: as_of 2025-03-01 is 365 days old"),
        (_table(source=None), DAY, "data/a.json: source must be"),
        ({"entries": []}, DAY, "data/a.json: missing envelope keys: as_of, kind, schema, source"),
        ("[1, 2]", DAY, "data/a.json: the table must be a JSON object"),
        ('{"as_of": 1, "as_of": 2}', DAY, "data/a.json: not valid JSON (duplicate keys: 'as_of'"),
    ],
)
def test_a_stale_or_malformed_table_fails(cat: Path, doc: object, today: dt.date, problem: str) -> None:
    _put(cat, "data/a.json", doc)
    found = cdt.problems(today, cat)
    assert len(found) == 1
    assert found[0].startswith(problem), found


def test_failures_name_every_table_and_exit_one(cat: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _put(cat, "data/a.json", _table(as_of="2020-01-01"))
    _put(cat, "base/p/data/b.json", "")
    assert cdt.main(["--today", "2026-03-01"], cat) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "data tables are malformed or stale on 2026-03-01 (re-check each against its sources):"
    assert out[1].startswith("  base/p/data/b.json: not valid JSON")
    assert out[2].startswith("  data/a.json: as_of 2020-01-01 is 2251 days old")


def test_a_legacy_table_is_skipped_and_a_missing_one_fails(cat: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _put(cat, "base/p/data/old.json", '{"rules": []}')
    monkeypatch.setattr(cdt, "LEGACY", {"base/p/data/old.json": "x (pre-D7)", "base/p/data/gone.json": "y"})
    assert cdt.problems(DAY, cat) == ["base/p/data/gone.json: listed in LEGACY but not found; delete the entry"]


def test_no_tables_is_zero_checked(cat: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cdt.main(["--today", "2026-03-01"], cat) == 0
    assert "0 checked" in capsys.readouterr().out


def test_today_defaults_to_the_real_utc_date(cat: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cdt.main([], cat) == 0
    assert capsys.readouterr().out.endswith(f"fresh on {dt.datetime.now(dt.UTC).date()}\n")


@pytest.mark.parametrize("value", ["2026-2-1", "2026-02-30", "tomorrow", "2026-02-01T00:00", chr(0xFF12) + "026-02-01"])
def test_a_bad_today_is_a_usage_error(value: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cdt.main(["--today", value])
    assert exc.value.code == 2
    assert "--today" in capsys.readouterr().err


def test_the_script_runs_on_its_own() -> None:
    script = ROOT / "tools" / "check_data_tables.py"
    done = subprocess.run(
        [sys.executable, script, "--today", "2026-10-02"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0
    assert done.stdout.startswith("data tables: ")
    assert done.stdout.endswith(" checked, fresh on 2026-10-02\n")


@pytest.mark.parametrize(
    "rel",
    [
        "data/a.json5",
        "data/a.jsonc",
        "data/a.json ",
        "data/sub/a.json",
        "base/p/data.json/data/x/a.json",
        "lib/pkg/data/sub/a.json",
        ".agents/policies/p/data/sub/a.json",
        "".join(map(chr, (0xFF24, 0xFF21, 0xFF34, 0xFF21))) + "/a.json",
    ],
)
def test_a_table_anywhere_but_a_plain_data_folder_is_found_and_refused(cat: Path, rel: str) -> None:
    _put(cat, rel, _table())
    (found,) = cdt.problems(DAY, cat)
    assert "a table must be a *.json file directly in a folder named data" in found


def test_a_table_in_any_top_level_folder_is_judged(cat: Path) -> None:
    _put(cat, "measurements/data/a.json", _table(as_of="2020-01-01"))
    (found,) = cdt.problems(DAY, cat)
    assert found.startswith("measurements/data/a.json: as_of 2020-01-01 is")


def test_test_fixtures_and_the_framework_checkout_are_not_tables(cat: Path) -> None:
    for top in ("tests", ".framework", ".git", "node_modules"):
        _put(cat, f"{top}/data/a.json", "{}")
    assert cdt.problems(DAY, cat) == []


def test_symlinked_tables_and_data_folders_are_reported_not_followed(
    cat: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("outside")
    _put(outside, "data/a.json", _table(as_of="2020-01-01"))
    (cat / "base" / "p" / "data").symlink_to(outside / "data", target_is_directory=True)
    _put(cat, "data/real.json", _table())
    (cat / "data" / "link.json").symlink_to(outside / "data" / "a.json")
    found = cdt.problems(DAY, cat)
    assert found == [
        "base/p/data: a table must be a *.json file directly in a folder named data",
        "data/link.json: a table and its data folder must not be symlinks",
    ]


def test_a_newline_in_a_path_cannot_forge_an_output_line(cat: Path) -> None:
    _put(cat, "data/a\nok.json", "{}")
    (found,) = cdt.problems(DAY, cat)
    assert found.startswith("'data/a\\nok.json': ")


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ('{"rules": [], "kind": "ioc"}', "listed in LEGACY but carries kind: check it as a table"),
        ('{"as_of": "2026-01-01"}', "listed in LEGACY but carries as_of"),
        ("not json", "listed in LEGACY but unreadable"),
    ],
)
def test_a_legacy_file_that_gains_an_envelope_or_breaks_fails(
    cat: Path, monkeypatch: pytest.MonkeyPatch, text: str, problem: str
) -> None:
    _put(cat, "base/p/data/old.json", text)
    monkeypatch.setattr(cdt, "LEGACY", {"base/p/data/old.json": "x (pre-D7)"})
    (found,) = cdt.problems(DAY, cat)
    assert found.startswith(f"base/p/data/old.json: {problem}")

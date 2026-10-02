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


def test_every_legacy_entry_exists_and_nothing_else_is_skipped() -> None:
    found = {p.relative_to(ROOT).as_posix() for p in cdt.tables(ROOT)}
    assert set(cdt.LEGACY) <= found
    assert all(reason.endswith("(pre-D7)") for reason in cdt.LEGACY.values())


def test_tables_are_found_at_the_root_and_at_any_depth_in_a_policy_whatever_the_case(cat: Path) -> None:
    for rel in ("Data/a.json", "base/p/implementations/data/b.json", "base/p/x/y/DATA/c.JSON"):
        _put(cat, rel, _table())
    for rel in ("data/sub/d.json", "base/p/data.json", "base/p/implementations/data/e.yaml", "tests/data/f.json"):
        _put(cat, rel, "{}")
    assert sorted(p.name for p in cdt.tables(cat)) == ["a.json", "b.json", "c.JSON"]


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
    assert (done.returncode, done.stdout) == (0, "data tables: 0 checked, fresh on 2026-10-02\n")

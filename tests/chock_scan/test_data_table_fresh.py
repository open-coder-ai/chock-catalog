"""chock_scan.data_table: freshness on an injected date, seeded fuzzing, the real-file corpus, and time bounds.

Property cases draw from a seeded generator (hypothesis is not a dev dependency here), so a
failure reproduces from its seed.
"""

from __future__ import annotations

import datetime as dt
import json
import time
from pathlib import Path
from types import ModuleType

import pytest
from trees import ROOT

from .dtcommon import IDS, SOURCES, load_module, rng, table, write

SEEDS = range(60)
AS_OF = dt.date(2026, 1, 15)


@pytest.fixture(params=SOURCES, ids=IDS)
def dt_(request: pytest.FixtureRequest) -> ModuleType:
    return load_module(request.param)


@pytest.mark.parametrize(("kind", "days"), [("ioc", 120), ("top-n", 365), ("curated", 365)])
def test_a_table_is_fresh_until_its_kinds_limit_and_stale_on_that_day(dt_: ModuleType, kind: str, days: int) -> None:
    doc = table(kind=kind)
    assert dt_.KINDS[kind] == days
    for age in (0, 1, days - 1):
        assert dt_.staleness(doc, AS_OF + dt.timedelta(days=age)) == []
        dt_.check_fresh(doc, AS_OF + dt.timedelta(days=age))
    for age in (days, days + 1, 10 * days):
        with pytest.raises(dt_.StaleError) as err:
            dt_.check_fresh(doc, AS_OF + dt.timedelta(days=age), "t.json")
        assert err.value.problems == [
            f"as_of {AS_OF} is {age} days old; a {kind} table must be re-checked within {days} days"
        ]
        assert isinstance(err.value, dt_.TableError)


def test_a_future_as_of_is_stale_so_it_cannot_buy_time(dt_: ModuleType) -> None:
    assert dt_.staleness(table(), AS_OF - dt.timedelta(days=1)) == [f"as_of {AS_OF} is after today (2026-01-14)"]


def test_staleness_refuses_a_bad_envelope_rather_than_passing_it(dt_: ModuleType) -> None:
    assert dt_.staleness(table(kind="forever"), AS_OF) == ["kind must be one of curated, ioc, top-n"]
    assert dt_.staleness(table(as_of=None), AS_OF) == ["missing envelope keys: as_of"]


@pytest.mark.parametrize("today", [dt.datetime(2026, 1, 15, tzinfo=dt.UTC), "2026-01-15", None, 20260115])
def test_today_must_be_a_date(dt_: ModuleType, today: object) -> None:
    with pytest.raises(TypeError, match=r"today must be a datetime\.date"):
        dt_.staleness(table(), today)


@pytest.mark.parametrize("seed", SEEDS)
def test_freshness_agrees_with_date_arithmetic(dt_: ModuleType, seed: int) -> None:
    r = rng(seed)
    kind = r.choice(sorted(dt_.KINDS))
    as_of = dt.date(2020, 1, 1) + dt.timedelta(days=r.randrange(0, 3000))
    today = as_of + dt.timedelta(days=r.randrange(-30, 800))
    found = dt_.staleness(table(kind=kind, as_of=as_of.isoformat()), today)
    assert (found == []) == (as_of <= today and (today - as_of).days < dt_.KINDS[kind])


def _mutate(r: object, text: str) -> str:
    """Delete, duplicate, or insert JSON-significant or hostile characters at a few points."""
    pool = [*'{}[]",:\\ \t\r\n0-eE.', "NaN", "/*", *map(chr, (0xFEFF, 0, 0xD800, 0x85, 0x2028))]
    chars = list(text)
    for _ in range(r.randrange(1, 6)):
        at = r.randrange(0, len(chars) + 1)
        op = r.randrange(3)
        if op == 0 and chars:
            del chars[min(at, len(chars) - 1)]
        elif op == 1 and chars:
            chars.insert(at, chars[min(at, len(chars) - 1)])
        else:
            chars.insert(at, r.choice(pool))
    return "".join(chars)


@pytest.mark.parametrize("seed", SEEDS)
def test_mutated_tables_load_or_raise_table_error_never_anything_else(
    dt_: ModuleType, tmp_path: Path, seed: int
) -> None:
    r = rng(seed)
    text = json.dumps(table(source={"a": "https://example.org"}), indent=r.choice([None, 1, 2]))
    for i in range(20):
        path = tmp_path / f"{i}.json"
        path.write_bytes(_mutate(r, text).encode("utf-8", "surrogatepass"))
        try:
            doc = dt_.load(path, kind="curated", schema=1, keys={"rows"})
        except dt_.TableError as exc:
            assert exc.problems
            assert all(isinstance(p, str) and p for p in exc.problems)
        else:
            assert not dt_.envelope_problems(doc)
            assert set(doc) == {"schema", "kind", "as_of", "source", "rows"}


@pytest.mark.parametrize("seed", SEEDS)
def test_random_values_in_every_envelope_slot_never_crash(dt_: ModuleType, seed: int) -> None:
    r = rng(seed)
    values = [None, True, 0, 1, -1, 2**70, 1.5, "", "x", "2026-01-15", "ioc", [], {}, ["ioc"], {"a": 1}]
    values += ["https://example.org", {"a": "https://a.b"}, {"": ""}, "\ud800", "a" * 600]
    doc = {k: r.choice(values) for k in ("schema", "kind", "as_of", "source") if r.random() < 0.9}
    found = dt_.envelope_problems(doc)
    assert all(isinstance(p, str) for p in found)
    if not found:
        assert isinstance(dt_.staleness(doc, AS_OF), list)


def _repo_json() -> list[Path]:
    skip = {".git", ".framework", "node_modules"}
    return sorted(p for p in ROOT.rglob("*.json") if not skip & set(p.relative_to(ROOT).parts))


def test_every_json_file_in_the_repo_parses_or_is_refused_explicitly(dt_: ModuleType) -> None:
    """The real-world corpus: package, lock, config, rule-data and fixture JSON, hostile ones included."""
    files = _repo_json()
    assert len(files) > 20
    parsed = 0
    for path in files:
        try:
            doc = dt_.read(path, limit=dt_.LIMIT)
        except dt_.TableError as exc:
            assert exc.problems, path
        else:
            parsed += not dt_.envelope_problems(doc)
    assert parsed >= 3


@pytest.mark.parametrize(
    "text",
    [
        "[" * 400_000 + "]" * 400_000,
        '{"a": "' + "\\" * 2 * 1_000_000 + '"}',
        "{" + ",".join(f'"k{i}": [{i}]' for i in range(200_000)) + "}",
        "{" + ",".join(f'"k": {i}' for i in range(200_000)) + "}",
        '{"schema": 1, "kind": "curated", "as_of": "2026-01-15", "source": "' + "a" * 2_000_000 + '"}',
        '{"source": "https://' + "a." * 500_000 + '"}',
        '{"source": "https://a' + "-" * 1_000_000 + ' "}',
    ],
    ids=["deep", "escapes", "wide", "duplicates", "long-source", "url-dots", "url-dashes"],
)
def test_pathological_input_is_judged_in_bounded_time(dt_: ModuleType, tmp_path: Path, text: str) -> None:
    path = write(tmp_path / "t.json", text)
    start = time.monotonic()
    with pytest.raises(dt_.TableError):
        dt_.read(path)
    assert time.monotonic() - start < 5


def test_the_size_cap_refuses_before_parsing(dt_: ModuleType, tmp_path: Path) -> None:
    path = write(tmp_path / "t.json", " " * (dt_.LIMIT + 1))
    with pytest.raises(dt_.TableError, match="larger than"):
        dt_.read(path)

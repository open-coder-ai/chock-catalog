"""tools/triage_tables.py: the EP-17 triage table loads, stays fresh, and keeps the shape its sources gave it."""

from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path

import pytest
import triage_tables as tt

AS_OF = dt.date(2026, 10, 1)


@pytest.fixture
def doc() -> dict:
    return copy.deepcopy(json.loads(tt.TABLE.read_text(encoding="utf-8")))


def found(doc: dict, today: dt.date = AS_OF) -> list[str]:
    return tt.problems(doc, today)


def test_the_committed_table_is_valid_and_fresh_today() -> None:
    table = tt.load()
    assert table["schema"] == 1
    assert table["verdicts"]["high"] == "deny"


def test_the_committed_table_is_valid_on_its_own_date(doc: dict) -> None:
    assert found(doc) == []
    assert tt.load(today=AS_OF)["as_of"] == AS_OF.isoformat()


def test_load_refuses_with_every_problem(tmp_path: Path, doc: dict) -> None:
    doc["schema"] = 2
    doc["verdicts"]["high"] = "ask"
    bad = tmp_path / "triage.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(tt.TableError, match=r"schema must be 1(.|\n)*verdicts\.high must be at least deny"):
        tt.load(bad, today=AS_OF)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"{", "unreadable: Expecting"),
        (b"\xff\xfe{}", "unreadable: 'utf-8' codec"),
        (b"[" * 100_000, "unreadable: maximum recursion"),
        (b'{"schema": 1, "schema": 1}', "unreadable: duplicate keys: schema"),
    ],
)
def test_load_refuses_what_it_cannot_read(tmp_path: Path, raw: bytes, expected: str) -> None:
    bad = tmp_path / "triage.json"
    bad.write_bytes(raw)
    with pytest.raises(tt.TableError, match=expected):
        tt.load(bad, today=AS_OF)


def test_load_refuses_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(tt.TableError, match="unreadable"):
        tt.load(tmp_path / "absent.json", today=AS_OF)


def test_a_duplicated_never_list_is_refused_not_last_one_wins(tmp_path: Path) -> None:
    text = tt.TABLE.read_text(encoding="utf-8").replace('"never_excluded": {', '"never_excluded": {"dirs": [], ', 1)
    bad = tmp_path / "triage.json"
    bad.write_text(text, encoding="utf-8")
    with pytest.raises(tt.TableError, match="duplicate keys: dirs"):
        tt.load(bad, today=AS_OF)


@pytest.mark.parametrize("value", [[], "x", 1, None])
def test_a_non_object_table_is_refused(value: object) -> None:
    assert tt.problems(value, AS_OF) == ["the table must be a JSON object"]


def test_stale_after_max_age(doc: dict) -> None:
    assert found(doc, AS_OF + dt.timedelta(days=tt.MAX_AGE_DAYS)) == []
    assert found(doc, AS_OF + dt.timedelta(days=tt.MAX_AGE_DAYS + 1)) == [
        f"as_of 2026-10-01 is older than {tt.MAX_AGE_DAYS} days: re-review the table against its sources"
    ]


@pytest.mark.parametrize("as_of", ["2026-13-01", "yesterday", 20261001, "", "2026-10-01T00:00:00"])
def test_as_of_must_be_an_iso_date(doc: dict, as_of: object) -> None:
    doc["as_of"] = as_of
    assert found(doc) == ["as_of must be an ISO date (YYYY-MM-DD)"]


def test_as_of_cannot_be_future_dated_to_extend_its_life(doc: dict) -> None:
    doc["as_of"] = "2026-10-02"
    assert found(doc) == ["as_of 2026-10-02 is in the future"]


def test_the_age_limit_is_code_not_data(doc: dict) -> None:
    doc["max_age_days"] = 99999
    assert found(doc) == ["unknown keys: max_age_days"]


def test_missing_keys_are_named(doc: dict) -> None:
    del doc["precedents"], doc["source"]
    assert found(doc) == ["missing keys: precedents, source"]


@pytest.mark.parametrize("schema", [True, 1.0, "1", 2])
def test_schema_is_the_integer_one(doc: dict, schema: object) -> None:
    doc["schema"] = schema
    assert found(doc) == ["schema must be 1"]


@pytest.mark.parametrize(
    "value",
    [
        {"r11": ""},
        {"r11": 3},
        {"r11": "http://x.example"},
        {"r11": "https://"},
        {"r11": "a/b:../x"},
        {"r11": "a/b:c/../d"},
    ],
)
def test_source_values_must_be_https_or_repo_paths(doc: dict, value: dict) -> None:
    doc["source"] |= value
    assert found(doc) == ["source values must be https:// URLs or owner/repo:path references"]


@pytest.mark.parametrize("value", [{}, []])
def test_source_must_be_a_non_empty_object(doc: dict, value: object) -> None:
    doc["source"] = value
    assert "source must be a non-empty object of id to URL or repo path" in found(doc)


def test_every_declared_source_is_cited(doc: dict) -> None:
    doc["source"]["spare"] = "https://example.org/x"
    assert found(doc) == ["source 'spare' is cited by no entry"]


@pytest.mark.parametrize("cites", [["nowhere"], [], "r11", [3], {}])
def test_an_entry_must_cite_declared_sources(doc: dict, cites: object) -> None:
    entry = doc["precedents"][0]
    entry["source"] = cites
    where = f"precedents.{entry['id']}"
    expected = f"{where}: source 'nowhere' is not in source" if cites == ["nowhere"] else f"{where}: source must be"
    assert any(p.startswith(expected) for p in found(doc)), found(doc)


@pytest.mark.parametrize("use", ["", "​", "  ", 3])
def test_use_must_be_text(doc: dict, use: object) -> None:
    doc["use"] = use
    assert found(doc) == ["use must be non-empty text"]


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda e: e.update(id="Bad Id"), "id 'Bad Id' must be kebab-case"),
        (lambda e: e.update(text=""), "text must be 1..300 characters"),
        (lambda e: e.update(text="x" * 301), "text must be 1..300 characters"),
        (lambda e: e.update(extra=1), "unknown keys: extra"),
        (lambda e: e.pop("source"), "missing keys: source"),
        (lambda e: e.update(unless=""), "unless must be 1..300 characters"),
        (lambda e: e.pop("unless"), "must keep its unless clause"),
        (
            lambda e: e.update(id="command-injection"),
            "not a known entry; a new exclusion or precedent is a code change",
        ),
    ],
)
def test_finding_entries_are_closed_and_bounded(doc: dict, mutate, expected: str) -> None:
    mutate(doc["finding_exclusions"][0])
    assert any(expected in p for p in found(doc)), found(doc)


@pytest.mark.parametrize("key", ["finding_exclusions", "precedents", "path_exclusions", "not_adopted"])
def test_lists_must_be_lists_of_objects(doc: dict, key: str) -> None:
    doc[key] = "x"
    assert any(p.startswith(f"{key} must be a") for p in found(doc)), found(doc)
    doc[key] = ["x"]
    assert f"{key}[0] must be an object" in found(doc)


@pytest.mark.parametrize("key", ["finding_exclusions", "precedents", "path_exclusions"])
def test_emptying_a_list_that_only_loosens_is_allowed(doc: dict, key: str) -> None:
    doc[key] = []
    assert not [p for p in found(doc) if p.startswith(key)], found(doc)


def test_not_adopted_must_not_be_empty(doc: dict) -> None:
    doc["not_adopted"] = []
    assert "not_adopted must be a non-empty list" in found(doc)


def test_ids_are_unique_across_every_list(doc: dict) -> None:
    doc["precedents"].append(copy.deepcopy(doc["finding_exclusions"][1]))
    assert any(p == f"duplicate id '{doc['finding_exclusions'][1]['id']}'" for p in found(doc)), found(doc)


def test_not_adopted_cannot_be_cut(doc: dict) -> None:
    doc["not_adopted"] = doc["not_adopted"][:1]
    assert [p for p in found(doc) if p.startswith("not_adopted must keep")] == [
        f"not_adopted must keep {i}" for i in sorted(tt.NOT_ADOPTED_IDS - {doc["not_adopted"][0]["id"]})
    ]


def test_not_adopted_names_the_upstream_rule_and_why(doc: dict) -> None:
    doc["not_adopted"][0]["why"] = ""
    assert found(doc) == [f"not_adopted.{doc['not_adopted'][0]['id']}: why must be 1..300 characters"]


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ({"high": "ask", "medium": "ask", "low": "allow"}, "verdicts.high must be at least deny"),
        ({"high": "deny", "medium": "allow", "low": "allow"}, "verdicts.medium must be at least ask"),
        ({"high": "deny", "medium": "allow", "low": "ask"}, "verdicts must not loosen as severity rises"),
        ({"high": "deny", "medium": "ask"}, "verdicts must map exactly high, low, medium"),
        ({"high": "deny", "medium": "warn", "low": "allow"}, "verdicts.medium must be one of allow, ask, deny"),
        ([], "verdicts must map exactly high, low, medium"),
    ],
)
def test_severity_verdicts(doc: dict, verdicts: object, expected: str) -> None:
    doc["verdicts"] = verdicts
    assert expected in found(doc)


@pytest.mark.parametrize(
    ("rank_tier", "expected"),
    [
        (
            {"1": "off", "2": "off", "3": "off", "4": "ask", "5": "block"},
            "rank_tier.5 must be one of advisory, ask, off",
        ),
        ({"1": "ask", "2": "off", "3": "off", "4": "ask", "5": "ask"}, "rank_tier must not loosen as rank rises"),
        ({"1": "off", "2": "off", "3": "off", "4": "off", "5": "off"}, "rank_tier.5 must be at least ask"),
        ({"1": "off", "2": "off", "3": "off", "4": "advisory", "5": "ask"}, "rank_tier.4 must be at least ask"),
        ({"1": "off"}, "rank_tier must map exactly 1, 2, 3, 4, 5"),
        ("x", "rank_tier must map exactly 1, 2, 3, 4, 5"),
    ],
)
def test_rank_tier(doc: dict, rank_tier: object, expected: str) -> None:
    doc["rank_tier"] = rank_tier
    assert expected in found(doc)


@pytest.mark.parametrize("value", [0, 9, 10, 8.0, "8", True])
def test_confidence_floor_cannot_be_raised_to_hide_findings(doc: dict, value: object) -> None:
    doc["report_min_confidence"] = value
    assert found(doc) == ["report_min_confidence must be an integer 1..8 (raising it hides findings)"]


@pytest.mark.parametrize("kind", ["ioc", "top-n", "", None, 1])
def test_the_kind_must_be_curated_so_a_data_edit_cannot_shorten_or_relabel_it(doc: dict, kind: object) -> None:
    doc["kind"] = kind
    assert found(doc) == ["kind must be curated (the D7 envelope; one year, as MAX_AGE_DAYS)"]

"""tools/triage_tables.py: the EP-17 triage table loads, stays fresh, and can never be edited looser."""

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
    with pytest.raises(tt.TableError, match=r"schema must be 1(.|\n)*verdicts\.high must be deny"):
        tt.load(bad, today=AS_OF)


def test_load_refuses_unparseable_json(tmp_path: Path) -> None:
    bad = tmp_path / "triage.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(tt.TableError, match="not valid JSON"):
        tt.load(bad, today=AS_OF)


@pytest.mark.parametrize("value", [[], "x", 1, None])
def test_a_non_object_table_is_refused(value: object) -> None:
    assert tt.problems(value, AS_OF) == ["the table must be a JSON object"]


# --- freshness (D7): a stale table breaks CI, it does not rot ---------------------------------


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


# --- shape ---------------------------------------------------------------------------------------


def test_missing_keys_are_named(doc: dict) -> None:
    del doc["precedents"], doc["source"]
    assert found(doc) == ["missing keys: precedents, source"]


@pytest.mark.parametrize("source", [{}, [], {"r": ""}, {"r": 3}, {"r": "http://x.example"}, {"r": "../x"}])
def test_sources_must_be_https_or_repo_paths(doc: dict, source: object) -> None:
    doc["source"] = source
    assert any(p.startswith("source") for p in found(doc)), found(doc)


def test_an_entry_citing_an_unknown_source_is_refused(doc: dict) -> None:
    doc["precedents"][0]["source"] = "nowhere"
    assert found(doc) == [f"precedents.{doc['precedents'][0]['id']}: source 'nowhere' is not in source"]


@pytest.mark.parametrize("field", ["use"])
def test_use_must_be_text(doc: dict, field: str) -> None:
    doc[field] = ""
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
    ],
)
def test_finding_entries_are_closed_and_bounded(doc: dict, mutate, expected: str) -> None:
    entry = doc["finding_exclusions"][0]
    mutate(entry)
    assert any(expected in p for p in found(doc)), found(doc)


@pytest.mark.parametrize("key", ["finding_exclusions", "precedents", "path_exclusions", "not_adopted"])
def test_lists_must_be_non_empty_lists_of_objects(doc: dict, key: str) -> None:
    doc[key] = []
    assert found(doc) == [f"{key} must be a non-empty list"]
    doc[key] = ["x"]
    assert found(doc) == [f"{key}[0] must be an object"]


def test_ids_are_unique_across_every_list(doc: dict) -> None:
    doc["precedents"][0]["id"] = doc["finding_exclusions"][0]["id"]
    assert found(doc) == [f"duplicate id '{doc['precedents'][0]['id']}'"]


def test_not_adopted_names_the_upstream_rule_and_why(doc: dict) -> None:
    doc["not_adopted"][0] = {"id": "x", "upstream": "y", "why": "", "source": "r11"}
    assert found(doc) == ["not_adopted.x: why must be 1..300 characters"]


# --- invariants that make a looser edit fail ------------------------------------------------------


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ({"high": "ask", "medium": "ask", "low": "allow"}, "verdicts.high must be deny"),
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


@pytest.mark.parametrize("dropped", [*sorted(tt.REQUIRED_NEVER_DIRS)[:2], "AGENTS.md"])
def test_never_excluded_cannot_shrink_below_the_code_floor(doc: dict, dropped: str) -> None:
    for key in ("dirs", "names"):
        doc["never_excluded"][key] = [v for v in doc["never_excluded"][key] if v != dropped]
    assert found(doc) == [f"never_excluded must keep {dropped}"]


def test_never_excluded_is_a_closed_object(doc: dict) -> None:
    doc["never_excluded"] = {"dirs": "x", "names": [""]}
    assert found(doc) == [
        "never_excluded.dirs must be a list of strings",
        "never_excluded.names must be a list of strings",
    ]
    doc["never_excluded"] = []
    assert found(doc) == ["never_excluded must have exactly dirs, names"]


@pytest.mark.parametrize(
    ("dirs", "names", "expected"),
    [
        ([".github"], [], "path_exclusions.tests: dirs entry '.github' is never excluded"),
        ([], ["*.md"], "path_exclusions.tests: names glob '*.md' matches never-excluded 'AGENTS.md'"),
        ([], ["SKILL*"], "path_exclusions.tests: names glob 'SKILL*' matches never-excluded 'SKILL.md'"),
        ([], ["*.YAML"], "path_exclusions.tests: names glob '*.YAML' matches never-excluded 'manifest.yaml'"),
        (["a/b"], [], "path_exclusions.tests: dirs entry 'a/b' must be one path segment"),
        ([], [], "path_exclusions.tests: needs dirs or names"),
        ("x", [], "path_exclusions.tests: dirs must be a list of strings"),
    ],
)
def test_a_path_exclusion_can_never_cover_agent_config(doc: dict, dirs, names, expected: str) -> None:
    entry = next(e for e in doc["path_exclusions"] if e["id"] == "tests")
    entry.update(dirs=dirs, names=names)
    assert expected in found(doc)


# --- matching -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_app.py", "tests"),
        ("pkg/sub/test_app.py", "tests"),
        ("src/app_test.go", "tests"),
        ("web/__tests__/x.js", "tests"),
        ("docs/guide/setup.md", "docs"),
        ("vendor/github.com/x/y.go", "vendored"),
        ("node_modules/left-pad/index.js", "vendored"),
        ("api/user.pb.go", "generated"),
        ("./tests\\unit\\x.py", "tests"),
    ],
)
def test_excluded_paths(path: str, expected: str) -> None:
    assert tt.excluded(tt.load(), path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "src/app.py",
        "contests/score.py",
        "latest/app.py",
        "docs/AGENTS.md",
        "tests/CLAUDE.md",
        "vendor/x/SKILL.md",
        "tests/.github/workflows/ci.yml",
        "docs/.claude/settings.json",
        "Tests/Agents.md",
        "tests/../src/app.py",
        "../tests/x.py",
        "/tests/x.py",
        "",
        "tests/.CHOCK/config.yaml",
        "base/p/implementations/test_guard.py",
    ],
)
def test_paths_that_stay_in_scope(path: str) -> None:
    assert tt.excluded(tt.load(), path) is None

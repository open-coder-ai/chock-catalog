"""tools/triage_tables.py: no table edit and no path spelling drops agent config from a review."""

from __future__ import annotations

import copy
import datetime as dt
import fnmatch
import json

import pytest
import triage_tables as tt

AS_OF = dt.date(2026, 10, 1)


@pytest.fixture
def doc() -> dict:
    return copy.deepcopy(json.loads(tt.TABLE.read_text(encoding="utf-8")))


def found(doc: dict) -> list[str]:
    return tt.problems(doc, AS_OF)


def test_the_code_floors_do_not_overlap_the_widest_exclusion() -> None:
    assert not tt.NEVER_DIRS & tt.EXCLUDABLE_DIRS
    assert not [(g, n) for g in tt.EXCLUDABLE_NAMES for n in tt.NEVER_NAMES if fnmatch.fnmatchcase(n.casefold(), g)]


@pytest.mark.parametrize(("key", "value"), [("dirs", v) for v in sorted(tt.NEVER_DIRS)])
def test_every_floor_dir_must_stay_listed(doc: dict, key: str, value: str) -> None:
    doc["never_excluded"][key].remove(value)
    assert found(doc) == [f"never_excluded.{key} must keep {value}"]


@pytest.mark.parametrize(("key", "value"), [("names", v) for v in sorted(tt.NEVER_NAMES)])
def test_every_floor_name_must_stay_listed(doc: dict, key: str, value: str) -> None:
    doc["never_excluded"][key].remove(value)
    assert found(doc) == [f"never_excluded.{key} must keep {value}"]


@pytest.mark.parametrize(("src", "dst", "value"), [("dirs", "names", ".github"), ("names", "dirs", "AGENTS.md")])
def test_moving_a_floor_entry_between_lists_is_refused(doc: dict, src: str, dst: str, value: str) -> None:
    doc["never_excluded"][src].remove(value)
    doc["never_excluded"][dst].append(value)
    assert found(doc) == [f"never_excluded.{src} must keep {value}"]


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
        (["workflows"], [], "dirs entry 'workflows' is wider than the code allows"),
        (["src"], [], "dirs entry 'src' is wider than the code allows"),
        ([], ["*.md"], "names glob '*.md' is wider than the code allows"),
        ([], ["*.py"], "names glob '*.py' is wider than the code allows"),
        ([], ["triage.json"], "names glob 'triage.json' is wider than the code allows"),
        ([], [], "needs dirs or names"),
        ("x", [], "dirs must be a list of strings"),
        ([], [1], "names must be a list of strings"),
    ],
)
def test_a_path_exclusion_cannot_widen_past_the_code(doc: dict, dirs, names, expected: str) -> None:
    entry = next(e for e in doc["path_exclusions"] if e["id"] == "tests")
    entry.update(dirs=dirs, names=names)
    assert found(doc) == [f"path_exclusions.tests: {expected}"]


def test_the_floor_wins_even_over_a_table_that_omits_it(doc: dict) -> None:
    doc["never_excluded"] = {"dirs": [], "names": []}
    doc["path_exclusions"][0]["dirs"].append("workflows")
    assert tt.excluded(doc, ".github/workflows/ci.yml") is None
    assert tt.excluded(doc, "docs/AGENTS.md") is None


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_app.py", "tests"),
        ("pkg/sub/test_app.py", "tests"),
        ("src/app_test.go", "tests"),
        ("web/__tests__/x.js", "tests"),
        ("./tests/unit/x.py", "tests"),
        ("docs/guide/setup.md", "docs"),
        ("vendor/github.com/x/y.go", "vendored"),
        ("node_modules/left-pad/index.js", "vendored"),
        ("api/user.pb.go", "generated"),
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
        "docs/CLAUDE.local.md",
        "docs/AGENTS.override.md",
        "docs/conf.py",
        "tests/conftest.py",
        "tests/CLAUDE.md",
        "vendor/x/SKILL.md",
        "tests/.github/workflows/ci.yml",
        "docs/.claude/settings.json",
        "tests/Agents.md",
        "tests/.CHOCK/config.yaml",
        "base/p/implementations/test_guard.py",
        "base/p/evals/test_x.py",
        "tests/../src/app.py",
        "../tests/x.py",
        "..",
        ".",
        "/tests/x.py",
        "~/tests/x.py",
        "C:/repo/tests/x.py",
        "C:\\repo\\tests\\x.py",
        "tests\\evil.py",
        "file:///tests/x.py",
        "tests/AGENTS.md ",
        "tests/AGENTS.md.",
        "tests/AGENTS.md::$DATA",
        "tests./x.py",
        "",
    ],
)
def test_paths_that_stay_in_scope(path: str) -> None:
    assert tt.excluded(tt.load(), path) is None

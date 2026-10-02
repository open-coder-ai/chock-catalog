"""compromised-package-ioc: the IOC table's loader, payload check, name and version normalisation, and lookups."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from policies.iockit import IMPL, TABLE, table

REAL = json.loads((IMPL / "data" / "ioc.json").read_text(encoding="utf-8"))


def write(tmp_path: Path, doc: dict) -> Path:
    folder = tmp_path / "data"
    folder.mkdir(exist_ok=True)
    path = folder / "ioc.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def problems(tmp_path: Path, doc: dict) -> str:
    with pytest.raises(table.data_table.TableError) as caught:
        table.load(write(tmp_path, doc))
    return str(caught.value)


def test_the_shipped_table_is_an_ioc_table_with_every_row_sourced() -> None:
    assert (REAL["kind"], REAL["schema"]) == ("ioc", 1)
    rows = REAL["packages"] + REAL["actions"] + REAL["files"]
    assert {r["source"] for r in rows} <= set(REAL["source"])
    assert len(TABLE.packages) == len(REAL["packages"])
    assert "reviewed pull request" in REAL["refresh"]


def test_the_shipped_table_is_fresh_for_120_days_and_no_longer() -> None:
    as_of = table.data_table.as_of(REAL)
    assert as_of is not None
    table.data_table.check_fresh(REAL, as_of)
    with pytest.raises(table.data_table.StaleError, match="120 days"):
        table.data_table.check_fresh(REAL, as_of.fromordinal(as_of.toordinal() + 120))


@pytest.mark.parametrize(
    ("eco", "name", "want"),
    [
        ("pypi", "LiteLLM", "litellm"),
        ("pypi", "Foo__Bar..baz", "foo-bar-baz"),
        ("crates", "Proc_Macro1", "proc-macro1"),
        ("npm", " @NX/DevKit ", "@nx/devkit"),
        ("go", "github.com/BoltDB-Go/bolt", "github.com/boltdb-go/bolt"),
        ("rubygems", "fastlane-plugin-proxy_teleram", "fastlane-plugin-proxy_teleram"),
    ],
)
def test_names_are_normalised_per_registry(eco: str, name: str, want: str) -> None:
    assert table.norm_name(eco, name) == want


@pytest.mark.parametrize(
    ("eco", "version", "want"),
    [
        ("npm", "=v1.14.1+build.5", "1.14.1"),
        ("npm", "V1.14.1", "1.14.1"),
        ("npm", "vnext", "vnext"),
        ("pypi", "1.82.7.0.0", "1.82.7"),
        ("pypi", "01.082.7RC1", "1.82.7rc1"),
        ("pypi", "0", "0"),
        ("pypi", "dev", "dev"),
        ("pypi", "0!1.82.7", "1.82.7"),
        ("pypi", "00!1.82.7", "1.82.7"),
        ("pypi", "1!1.82.7", "1!1.82.7"),
        ("go", "v1.3.1", "1.3.1"),
    ],
)
def test_versions_are_normalised_per_registry(eco: str, version: str, want: str) -> None:
    assert table.norm_version(eco, version) == want


def test_package_lookup_honours_exact_and_any_version_rows() -> None:
    assert TABLE.package("npm", "axios", "1.14.1").incident.startswith("axios")
    assert TABLE.package("npm", "axios", "1.14.0") is None
    assert TABLE.package("npm", "axios", None) is None
    assert TABLE.package("npm", "postmark-mcp", None) is not None
    assert TABLE.package("npm", "postmark-mcp", "9.9.9") is not None
    assert TABLE.package("npm", "left-pad", "1.3.0") is None
    assert TABLE.package("pypi", "LiteLLM", "1.82.7.0") is not None


@pytest.mark.parametrize(
    ("name", "ref", "listed"),
    [
        ("tj-actions/changed-files", "0E58ED8671D6B60D0890C21B07F8835ACE038E67", True),
        ("tj-actions/changed-files", "v46", True),
        ("tj-actions/changed-files", "0e58ed8", True),
        ("reviewdog/action-setup", "f0d342d24037bb11d26b9bd8496e0808ba32e9ec", True),
        ("reviewdog/action-setup", "f0d342e24037bb11d26b9bd8496e0808ba32e9ec", False),
        ("tj-actions/changed-files", "", True),
        ("tj-actions/changed-files", "ed68ef82c095e0d48ec87eccea555d944a631a4c", False),
        ("actions/checkout", "v4", False),
    ],
)
def test_action_lookup(name: str, ref: str, listed: bool) -> None:
    assert (TABLE.action(name, ref) is not None) is listed


def test_an_action_listed_only_by_commit_lets_its_tags_through() -> None:
    doc = copy.deepcopy(REAL)
    doc["actions"] = [dict(doc["actions"][0], mutable_refs=False)]
    pinned = table.Table(doc)
    assert pinned.action("tj-actions/changed-files", "v46") is None
    assert pinned.action("tj-actions/changed-files", "0e58ed8671d6b60d0890c21b07f8835ace038e67") is not None


@pytest.mark.parametrize(
    ("path", "listed"),
    [
        ("setup_bun.js", True),
        ("pkg/SETUP_BUN.JS", True),
        ("/abs/litellm_init.pth", True),
        (".claude/math_init.js", True),
        ("x/.Claude/Math_Init.js", True),
        ("math_init.js", False),
        ("setup-bun.js", False),
        ("not_setup_bun.js", False),
    ],
)
def test_file_lookup(path: str, listed: bool) -> None:
    assert (TABLE.file(path) is not None) is listed


def test_a_valid_table_loads_from_any_data_folder(tmp_path: Path) -> None:
    loaded = table.load(write(tmp_path, REAL))
    assert len(loaded.files) == len(REAL["files"])


def bad(**changes: object) -> dict:
    doc = copy.deepcopy(REAL)
    for where, value in changes.items():
        section, _, field = where.partition("__")
        if field:
            doc[section][0][field] = value
        else:
            doc[section] = value
    return doc


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        (bad(refresh=""), "refresh must be"),
        (bad(source="https://example.org/a", packages=REAL["packages"][:1]), "source must name a key"),
        (bad(packages__ecosystem="maven"), "ecosystem must be one of"),
        (bad(packages__versions=[]), "versions must be"),
        (bad(packages__versions="1.0.0"), "versions must be"),
        (bad(packages__versions=[" 1.0.0"]), "versions must be"),
        (bad(packages__name=" axios"), "name must be non-empty text"),
        (bad(packages__incident=""), "incident must be non-empty text"),
        (bad(packages__date="2025-9-8"), "date must be YYYY-MM-DD"),
        (bad(packages__source="nowhere"), "source must name a key"),
        (bad(packages=[*REAL["packages"], dict(REAL["packages"][0], name="ANSI-Regex")]), "repeats npm ansi-regex"),
        (bad(actions__name="tj-actions"), "must be owner/repo"),
        (bad(actions__refs=["v1"]), "lowercase hex commits"),
        (bad(actions__refs="0e58ed8671d6b60d0890c21b07f8835ace038e67"), "lowercase hex commits"),
        (bad(actions__mutable_refs="yes"), "must list refs or set mutable_refs"),
        (bad(actions=[dict(REAL["actions"][2], mutable_refs=False)]), "must list refs or set mutable_refs"),
        (bad(files__name="/etc/x"), "relative path"),
        (bad(files__name="a/../b"), "relative path"),
        (bad(files__name="a\\b"), "relative path"),
        (bad(packages=[{"name": "x"}]), "must be an object with exactly"),
        (bad(files=["setup_bun.js"]), "must be an object with exactly"),
        (bad(kind="curated"), "kind is curated, expected ioc"),
    ],
)
def test_a_malformed_table_is_refused_naming_the_problem(tmp_path: Path, doc: dict, message: str) -> None:
    assert message in problems(tmp_path, doc)

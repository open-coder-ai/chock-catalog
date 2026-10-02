"""tools/prose_counts.py writes SECURITY.md's and CONTRIBUTING.md's counts from registry.yaml."""

from __future__ import annotations

from pathlib import Path

import gen_registry
import prose_counts
import pytest
import yaml
from mechanism import CEILING, GUARD
from trees import ROOT

ROWS = [
    {"id": "text", "mechanism": "rule text only", "enforces": "advisory"},
    {"id": "warn", "mechanism": "warn-only gate", "enforces": "advisory"},
    {"id": "guard", "mechanism": "guard script", "enforces": CEILING[GUARD]},
    {"id": "regex", "mechanism": "content_regex", "enforces": "enforced-at-commit"},
    {"id": "zeta", "mechanism": "script", "enforces": "enforced-at-commit"},
    {"id": "alpha", "mechanism": "commit-time guard script + tool-use script gate", "enforces": "enforced-at-commit"},
]
SECURITY = "<!-- gen:advisory -->0<!-- /gen --> of <!-- gen:policies -->0<!-- /gen --> policies.\n"
CONTRIBUTING = "Run: <!-- gen:hook-program-ids --><!-- /gen -->\n"


@pytest.fixture
def catalog(tmp_path: Path) -> Path:
    (tmp_path / "registry.yaml").write_text(yaml.safe_dump({"policies": ROWS}), encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text(SECURITY, encoding="utf-8")
    (tmp_path / "CONTRIBUTING.md").write_text(CONTRIBUTING, encoding="utf-8")
    return tmp_path


def test_values_count_each_ceiling_and_list_the_hook_programs() -> None:
    assert prose_counts.values(ROWS) == {
        "policies": "6",
        "advisory": "2",
        "best-effort": "1",
        "enforced-at-commit": "3",
        "hook-programs": "2",
        "hook-program-ids": "`alpha`, `zeta`",
    }


def test_markers_are_filled_and_a_second_run_changes_nothing(catalog: Path) -> None:
    assert prose_counts.update(catalog, write=True) == [
        "SECURITY.md counts rewritten",
        "CONTRIBUTING.md counts rewritten",
    ]
    text = (catalog / "SECURITY.md").read_text(encoding="utf-8")
    assert text == "<!-- gen:advisory -->2<!-- /gen --> of <!-- gen:policies -->6<!-- /gen --> policies.\n"
    assert "<!-- gen:hook-program-ids -->`alpha`, `zeta`<!-- /gen -->" in (catalog / "CONTRIBUTING.md").read_text()
    assert prose_counts.update(catalog, write=False) == [
        "SECURITY.md counts already current",
        "CONTRIBUTING.md counts already current",
    ]


def test_check_mode_writes_nothing_and_reports_drift(catalog: Path) -> None:
    assert prose_counts.update(catalog, write=False)[0] == "SECURITY.md is stale: run python tools/gen_registry.py"
    assert (catalog / "SECURITY.md").read_text(encoding="utf-8") == SECURITY


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("No markers at all.\n", "no generated count markers"),
        ("<!-- gen:nonsense -->1<!-- /gen -->\n", "unknown count marker gen:nonsense"),
        ("<!-- gen:policies -->6<!-- /gen -->\nTwenty-two of the forty-two policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\nall 48 published policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\nnine are enforced\n", "line 2: hand-written count"),
        (
            "<!-- gen:policies -->6<!-- /gen -->\nsays. Twenty-two of the forty-two\npolicies here are advisory\n",
            "line 2: hand-written count",
        ),
        ("<!-- gen:policies -->6<!-- /gen -->\n**22** policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\nAnother 7 are best-effort\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n9 hook programs\n", "line 2: hand-written count"),
        (
            "<!-- gen:policies -->6<!-- /gen -->\n20 of the catalog's policies are advisory.\n",
            "line 2: hand-written count",
        ),
        ("<!-- gen:policies -->6<!-- /gen -->\n22&#160;policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n`48` policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n48+ policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n48 \u201csigned\u201d policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n48 published, signed policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n22&nbsp;policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n<b>22</b> policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n22 (of 42) policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n22 of the published catalog policies\n", "line 2: hand-written count"),
        (
            "<!-- gen:policies -->6<!-- /gen -->\n48 [policies](.agents/policies/INDEX.md)\n",
            "line 2: hand-written count",
        ),
        ("<!-- gen:policies -->6<!-- /gen -->\n48 (policies)\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n20 \u2014 all advisory\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\nAdvisory policies: 20.\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\nPolicy count: 48\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\nPolicies (48 total) ship manifests.\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n| Advisory policies | 20 |\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\nx < 3 and 48 policies > y\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n22 <!-- x\n --> policies\n", "line 2: hand-written count"),
        ("<!-- gen:policies -->6<!-- /gen -->\n<!--- gen:advisory --->12<!--- /gen --->\n", "line 2: malformed"),
        ("<!-- gen:policies-->42<!-- /gen --> policies\n", "line 1: malformed or unclosed gen marker"),
        ("<!-- gen:Policies -->42<!-- /gen --> policies\n", "line 1: malformed or unclosed gen marker"),
        (
            "<!-- gen:policies -->6<!-- /gen -->\n<!-- gen:advisory -->20 of\n\ntext\n<!-- gen:policies -->48<!-- /gen -->\n",
            "line 2: malformed or unclosed gen marker",
        ),
    ],
)
def test_a_file_that_could_drift_is_stale_and_left_unwritten(catalog: Path, text: str, problem: str) -> None:
    (catalog / "SECURITY.md").write_text(text, encoding="utf-8")
    results = prose_counts.update(catalog, write=True)
    assert any(line.startswith("SECURITY.md is stale: ") and problem in line for line in results), results
    assert (catalog / "SECURITY.md").read_text(encoding="utf-8") == text


@pytest.mark.parametrize(
    "line",
    [
        "The three rules",
        "eleven of them, including Claude Code",
        "within 7 days",
        "Three merged pull requests",
        "see PR #12 policy",
        "One folder per policy",
        "1. **Turn an advisory policy into an enforced one.**",
        "**1. A policy claims only what it can do.**",
        "Apache-2.0 policy text",
    ],
)
def test_counts_of_other_things_are_not_policy_counts(line: str) -> None:
    """Numbers that count something else, list markers and version numbers stay silent."""
    assert prose_counts.render(f"<!-- gen:policies -->1<!-- /gen -->\n{line}\n", {"policies": "1"})[1] == []


def test_gen_registry_writes_and_checks_the_prose(catalog: Path) -> None:
    assert gen_registry.update_prose(catalog, write=False).startswith("SECURITY.md is stale")
    assert gen_registry.update_prose(catalog) == "SECURITY.md counts rewritten\nCONTRIBUTING.md counts rewritten"


def test_the_committed_prose_counts_are_current() -> None:
    assert prose_counts.update(ROOT, write=False) == [
        "SECURITY.md counts already current",
        "CONTRIBUTING.md counts already current",
    ]

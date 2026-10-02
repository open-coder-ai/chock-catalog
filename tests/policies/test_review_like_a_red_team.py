"""review-like-a-red-team: an advisory skill that ships the EP-17 triage table it reasons with, unaltered."""

from __future__ import annotations

from pathlib import Path

import triage_tables as tt
import yaml
from mechanism import NONE, classify

POLICY = tt.ROOT / "base" / "review-like-a-red-team"
COPY = POLICY / "skill" / "references" / "triage.json"
SKILL = POLICY / "skills" / "review-like-a-red-team" / "SKILL.md"


def manifest() -> dict:
    return yaml.safe_load((POLICY / "manifest.yaml").read_text(encoding="utf-8"))


def test_the_shipped_table_is_the_catalog_table_byte_for_byte() -> None:
    assert COPY.read_bytes() == tt.TABLE.read_bytes(), "copy data/triage.json to skill/references/triage.json"


def test_the_shipped_table_passes_the_loader() -> None:
    assert tt.load(COPY)["schema"] == 1


def test_it_claims_no_gate() -> None:
    m = manifest()
    assert (m["artifact"], m["enforcement"]) == ("rule", "advise")
    assert "hook" not in m
    assert not (POLICY / "implementations").exists()
    assert classify(POLICY, m) == (NONE, "rule text only")


def test_it_says_it_is_advisory_and_writes_no_waiver() -> None:
    text = SKILL.read_text(encoding="utf-8")
    assert "advisory: this skill refuses nothing" in text
    assert "never write one" in text
    assert "Advisory: refuses nothing, writes no waiver, lowers no gate." in " ".join(manifest()["description"].split())


def test_the_rendered_skill_fits_its_budgets() -> None:
    assert len(SKILL.read_text(encoding="utf-8").splitlines()) <= 150
    assert len(" ".join(manifest()["description"].split())) <= 500
    assert len(COPY.read_text(encoding="utf-8").splitlines()) <= 300


def test_the_skill_names_only_table_keys_that_exist() -> None:
    text = (POLICY / "skill" / "body.md").read_text(encoding="utf-8")
    table = tt.load(COPY)
    named = {k for k in tt.KEYS if f"{k}" in text}
    assert {"never_excluded", "path_exclusions", "finding_exclusions", "precedents"} <= named
    assert {"report_min_confidence", "verdicts", "not_adopted"} <= named
    assert set(table["verdicts"].values()) <= {"deny", "ask", "allow"}
    assert Path(COPY).name in text

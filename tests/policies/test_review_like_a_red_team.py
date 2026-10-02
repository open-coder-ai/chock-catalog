"""review-like-a-red-team: an advisory skill that ships the EP-17 triage table it reasons with, unaltered."""

from __future__ import annotations

import json
import re

import triage_tables as tt
import yaml
from chock.validation.patterns import AGENT_SPECIFIC_PATTERNS, INJECTION_PATTERNS
from mechanism import NONE, classify

POLICY = tt.ROOT / "base" / "review-like-a-red-team"
COPY = POLICY / "skill" / "references" / "triage.json"
BODY = POLICY / "skill" / "body.md"
SKILL = POLICY / "skills" / "review-like-a-red-team" / "SKILL.md"


def manifest() -> dict:
    return yaml.safe_load((POLICY / "manifest.yaml").read_text(encoding="utf-8"))


def strings(value: object) -> list[str]:
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in [k, *strings(v)]]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return [value] if isinstance(value, str) else []


def test_the_shipped_table_is_the_catalog_table_byte_for_byte() -> None:
    assert COPY.read_bytes() == tt.TABLE.read_bytes(), "copy data/triage.json to skill/references/triage.json"


def test_the_shipped_table_passes_the_loader() -> None:
    assert tt.load(COPY)["schema"] == 1


def test_the_shipped_table_carries_no_injection_tripwire() -> None:
    """chock validate scans .md and .yaml only; the skill reads this JSON whole, so scan it here."""
    text = strings(json.loads(COPY.read_text(encoding="utf-8")))
    assert not [(p, s) for p in INJECTION_PATTERNS for s in text if re.search(p, s, re.IGNORECASE)]


def test_the_method_names_no_agent_vendor() -> None:
    """The table names vendor config files as path data; the method itself stays agent-agnostic."""
    text = BODY.read_text(encoding="utf-8") + manifest()["rule"]["text"]
    assert not [p.pattern for p in AGENT_SPECIFIC_PATTERNS if p.search(text)]


def test_it_claims_no_gate() -> None:
    m = manifest()
    assert (m["artifact"], m["enforcement"]) == ("rule", "advise")
    assert "hook" not in m
    assert not (POLICY / "implementations").exists()
    assert classify(POLICY, m) == (NONE, "rule text only")


def test_it_says_it_is_advisory_and_never_permits_a_waiver() -> None:
    text = SKILL.read_text(encoding="utf-8")
    assert "advisory: this skill refuses nothing" in text
    assert "Never write one" in text
    waiver_lines = [line for line in text.splitlines() if "waiver" in line.lower()]
    assert waiver_lines
    assert all(re.search(r"\bnever\b|\bno waiver\b|their own waiver", line, re.IGNORECASE) for line in waiver_lines), (
        waiver_lines
    )
    assert "Advisory: refuses nothing, writes no waiver, lowers no gate." in " ".join(manifest()["description"].split())


def test_the_rendered_skill_fits_its_budgets() -> None:
    assert len(SKILL.read_text(encoding="utf-8").splitlines()) <= 150
    assert len(" ".join(manifest()["description"].split())) <= 500
    assert len(COPY.read_text(encoding="utf-8").splitlines()) <= 300
    rule = manifest()["rule"]["text"].strip()
    assert len(rule.splitlines()) <= 2
    assert len(rule) <= 500


def test_the_triage_block_names_only_keys_the_table_has() -> None:
    body = BODY.read_text(encoding="utf-8")
    block = body.split("## Triage", 1)[1].split("```")[1]
    named = set(re.findall(r"\b[a-z]+(?:_[a-z]+)+\b", block))
    assert named, block
    assert named <= tt.KEYS, sorted(named - tt.KEYS)
    assert named >= {"never_excluded", "path_exclusions", "finding_exclusions", "report_min_confidence", "not_adopted"}
    assert re.search(r"\bprecedents\b", block)
    assert re.search(r"\bverdicts\b", block)


def test_wording_pin_excluded_paths_are_still_read() -> None:
    """A wording pin, not a behaviour test: rewording the carve-out must be a deliberate test edit."""
    block = BODY.read_text(encoding="utf-8").split("## Triage", 1)[1]
    assert "read its added and removed lines" in block
    assert "a hit -> review that\n                           file in full" in block

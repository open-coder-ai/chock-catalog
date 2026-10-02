"""tools/owasp_llm.py holds every OWASP LLM id a manifest names to the 2025 list."""

from __future__ import annotations

import check_registry
import owasp_llm
import pytest
import yaml
from trees import ROOT, policy_dirs


def test_the_2025_list_has_ten_entries_with_excessive_agency_at_llm06() -> None:
    assert list(owasp_llm.LLM_2025) == [f"LLM{n:02d}" for n in range(1, 11)]
    assert owasp_llm.LLM_2025["LLM06"] == "Excessive Agency"
    assert owasp_llm.LLM_2025["LLM03"] == "Supply Chain"


@pytest.mark.parametrize(
    ("compliance", "text", "problem"),
    [
        ({"owasp_llm": ["LLM06"]}, "", "compliance key 'owasp_llm': name the edition, 'owasp_llm_2025'"),
        ({"owasp_llm_2025": [{"control": "LLM11"}]}, "", "owasp_llm_2025: 'LLM11' is not an LLM01..LLM10 id"),
        ({"owasp_llm_2025": ["ASI03"]}, "", "owasp_llm_2025: 'ASI03' is not an LLM01..LLM10 id"),
        ({}, "note: (LLM03 Excessive Agency)", "text calls Excessive Agency LLM03; in the 2025 list it is LLM06"),
        ({}, "Anchors: excessive agency, LLM03", "text calls excessive agency LLM03; in the 2025 list it is LLM06"),
        ({}, "LLM10: Prompt Injection", "text calls Prompt Injection LLM10; in the 2025 list it is LLM01"),
    ],
)
def test_a_wrong_claim_is_named(compliance: dict, text: str, problem: str) -> None:
    assert owasp_llm.problems({"compliance": compliance}, text) == [problem]


@pytest.mark.parametrize(
    ("manifest", "text"),
    [
        ({}, ""),
        ({"compliance": None}, "no LLM ids here"),
        ({"compliance": {"owasp_asi": ["ASI03"]}}, "LLM06 (Excessive Agency), Supply Chain (LLM03)"),
        (
            {"compliance": {"owasp_llm_2025": ["LLM01", {"control": "LLM06", "coverage": "partial"}]}},
            "OWASP LLM01/ASI01",
        ),
    ],
)
def test_a_right_claim_passes(manifest: dict, text: str) -> None:
    assert owasp_llm.problems(manifest, text) == []


def test_every_published_policy_passes() -> None:
    for policy in policy_dirs():
        text = (policy / "manifest.yaml").read_text(encoding="utf-8")
        assert owasp_llm.problems(yaml.safe_load(text), text) == [], policy.name


def test_check_registry_fails_on_a_wrong_llm_name(monkeypatch, capsys) -> None:
    real = ROOT / "base" / "block-wildcard-agent-permissions" / "manifest.yaml"
    wrong = real.read_text(encoding="utf-8").replace("least-agency tool design", "LLM03 Excessive Agency; least-agency")
    assert wrong != real.read_text(encoding="utf-8")
    original = type(real).read_text

    def read_text(path, *args, **kwargs):
        return wrong if path == real else original(path, *args, **kwargs)

    monkeypatch.setattr(type(real), "read_text", read_text)
    assert check_registry.main() == 1
    out = capsys.readouterr().out
    assert "framework claims name the wrong entry:" in out
    assert "block-wildcard-agent-permissions: text calls Excessive Agency LLM03" in out

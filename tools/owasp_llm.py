"""OWASP Top 10 for LLM Applications 2025: the ids a manifest may claim, and the names they carry.

The edition is in the compliance key (`owasp_llm_2025`) because the numbering moved between
editions, and a compliance note shipped calling Excessive Agency LLM03 (it is LLM06 in 2025).
Source: https://genai.owasp.org/llm-top-10/ (the 2025 list; read 2026-10-02).
"""

from __future__ import annotations

import re
from typing import Any

KEY = "owasp_llm_2025"
LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
_NAME = "|".join(re.escape(name) for name in LLM_2025.values())
#: An id written beside a name, either way round: "LLM06 (Excessive Agency)", "Excessive Agency, LLM06".
_PAIR = re.compile(
    rf"\b(?P<id>LLM\d\d)\b[\s(:,-]{{0,4}}(?P<name>{_NAME})|(?P<name2>{_NAME})[\s(:,-]{{0,4}}(?P<id2>LLM\d\d)\b",
    re.I,
)


def _control(claim: Any) -> str:
    return str(claim.get("control") if isinstance(claim, dict) else claim)


def problems(manifest: dict[str, Any], text: str) -> list[str]:
    """What is wrong with the policy's LLM claims: an unknown key or id, or an id under another's name."""
    found = []
    for key, claims in (manifest.get("compliance") or {}).items():
        if key.startswith("owasp_llm") and key != KEY:
            found.append(f"compliance key {key!r}: name the edition, {KEY!r}")
        elif key == KEY:
            found += [
                f"{KEY}: {_control(c)!r} is not an LLM01..LLM10 id" for c in claims if _control(c) not in LLM_2025
            ]
    for match in _PAIR.finditer(text):
        llm_id = (match["id"] or match["id2"]).upper()
        name = match["name"] or match["name2"]
        if LLM_2025.get(llm_id, "").lower() != name.lower():
            want = next(i for i, n in LLM_2025.items() if n.lower() == name.lower())
            found.append(f"text calls {name} {llm_id}; in the 2025 list it is {want}")
    return found

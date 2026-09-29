"""Every rule's cases: text it must refuse, and the correct form it must stay silent on."""

from __future__ import annotations

from agentic_code_security.cases import approval_tools, code_prompt, comms_identity, execution, provenance, supply
from agentic_code_security.cases.case import Case

_MODULES = (execution, supply, approval_tools, comms_identity, code_prompt, provenance)
REFUSED: list[Case] = [c for m in _MODULES for c in m.REFUSED]
SILENT: list[Case] = [c for m in _MODULES for c in m.SILENT]

__all__ = ["REFUSED", "SILENT", "Case"]

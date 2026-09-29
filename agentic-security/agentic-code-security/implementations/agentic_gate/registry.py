"""The rule registry: every pack and every rule, keyed by the id a selection names."""

from __future__ import annotations

from agentic_gate.model import Pack, Rule
from agentic_gate.rules import approval, bounds, code, comms, execution, identity, promptmem, provenance, supply, tools

#: The order the catalogue reads in: the OWASP ASI packs by number, then code safety, then provenance.
_PACKS = (execution, supply, tools, approval, identity, comms, bounds, promptmem, code, provenance)


def packs() -> dict[str, Pack]:
    return {module.PACK.id: module.PACK for module in _PACKS}


def registry() -> dict[str, Rule]:
    """Every rule installed here, in catalogue order. A selection may name these ids and no others."""
    return {rule.id: rule for module in _PACKS for rule in module.RULES}

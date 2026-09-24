"""The rule registry: every pack, and every rule a pack contributes, keyed by the id a selection names."""

from __future__ import annotations

from chock_security.pack import Pack, Rule
from chock_security.rules import android, build, crypto, jakarta, java, logging, persistence, spring, templates

#: Registry order is the order the setup page and the contract show: the language, then the
#: frameworks on it, then the layers every framework shares, then the build and the platform.
_PACKS = (java, crypto, spring, jakarta, persistence, templates, logging, build, android)


def packs() -> dict[str, Pack]:
    """Every pack installed here, keyed by the name a selection uses."""
    return {module.PACK.id: module.PACK for module in _PACKS}


def registry() -> dict[str, Rule]:
    """Every rule installed here. A selection may name these ids and no others."""
    rules: dict[str, Rule] = {}
    for module in _PACKS:
        for rule in module.RULES:
            if rule.pack != module.PACK.id:
                msg = f"rule {rule.id!r} says pack {rule.pack!r} but is registered in {module.PACK.id!r}"
                raise ValueError(msg)
            if rule.id in rules:
                msg = f"rule id {rule.id!r} is registered twice"
                raise ValueError(msg)
            rules[rule.id] = rule
    return rules

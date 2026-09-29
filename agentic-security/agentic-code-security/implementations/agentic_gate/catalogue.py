"""The rule catalogue, rendered from the registry so a rule and its documentation cannot drift apart."""

from __future__ import annotations

from agentic_gate.model import Rule
from agentic_gate.registry import packs, registry

HEADER = """# Rule catalogue

Generated from the rule registry; a test fails when this file and the registry differ. Each rule
lists its pack, default verdict, weakness (CWE), OWASP Top 10 for Agentic Applications entry (ASI)
and the fix its refusal names. A selection (`.chock/agentic-security.json`) sets a verdict per
pack or per rule; a waiver is `# chock: allow <rule-id>` or `// chock: allow <rule-id>`, a human's
decision, and JSON is waived in the selection file only.
"""


def _rule(rule: Rule) -> str:
    return "\n".join(
        [
            f"### {rule.id}",
            f"- pack: {rule.pack}; default: {rule.default}; reads: {', '.join(rule.kinds)}; "
            f"CWE: {', '.join(rule.cwe) or 'none'}; ASI: {', '.join(rule.asi) or 'none'}",
            f"- what: {rule.refuses}",
            f"- why: {rule.why}",
            f"- fix: {rule.fix}",
            f"- silent on: {rule.silent_on}",
            f"- refs: {' '.join(rule.references)}",
            "",
        ]
    )


def render() -> str:
    rules = registry()
    parts = [HEADER]
    for pack in packs().values():
        asi = f" ({', '.join(pack.asi)})" if pack.asi else ""
        parts.append(f"## {pack.id}: {pack.title}{asi}\n\n{pack.covers}\n")
        parts.extend(_rule(rule) for rule in rules.values() if rule.pack == pack.id)
    return "\n".join(parts)

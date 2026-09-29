"""What each rule does when it fires. A selection sets verdicts; it never defines a rule."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from agentic_gate.model import VERDICTS, Rule

FILENAME = ".chock/agentic-security.json"
SCHEMA_VERSION = 1

_TOP_KEYS = frozenset({"version", "packs"})
_PACK_KEYS = frozenset({"verdict", "rules"})


class SelectionError(Exception):
    """A selection that does not say, unambiguously, what each known rule does."""


def _only(document: dict, allowed: frozenset[str], where: str) -> None:
    if unknown := sorted(set(document) - allowed):
        msg = f"{where} has unknown key(s) {unknown}; only {sorted(allowed)} are read"
        raise SelectionError(msg)


def _verdict(where: str, value: object) -> str:
    if value not in VERDICTS:
        msg = (
            f"{where} is {value!r}; a verdict is one of {list(VERDICTS)}. A selection says what rules "
            "that already exist do, and cannot carry patterns, severities or paths: a rule "
            "definable in JSON is a program in disguise."
        )
        raise SelectionError(msg)
    return str(value)


def _object(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        msg = f"{where} must be an object, got {type(value).__name__}"
        raise SelectionError(msg)
    return value


def _apply_pack(pack: str, declared: object, members: dict[str, Rule], verdicts: dict[str, str]) -> None:
    """A pack's own verdict first, then its rules one by one, so a rule can differ from its pack."""
    where = f"pack {pack!r}"
    body = _object(declared, where)
    _only(body, _PACK_KEYS, where)
    if "verdict" in body:
        verdicts.update(dict.fromkeys(members, _verdict(f"{where} verdict", body["verdict"])))
    spoken = _object(body.get("rules", {}), f"{where} 'rules'")
    if absent := sorted(set(spoken) - set(members)):
        msg = f"{where} names rule(s) it does not contain: {absent}"
        raise SelectionError(msg)
    for rule_id, value in spoken.items():
        verdicts[rule_id] = _verdict(f"rule {rule_id!r}", value)


def parse(raw: str, rules: Mapping[str, Rule]) -> dict[str, str]:
    """Every known rule's verdict, or SelectionError saying exactly what is wrong."""
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = f"selection is not valid JSON: {exc}"
        raise SelectionError(msg) from exc
    document = _object(document, "selection")
    _only(document, _TOP_KEYS, "selection")
    if document.get("version") != SCHEMA_VERSION:
        msg = f"selection version must be {SCHEMA_VERSION}, got {document.get('version')!r}"
        raise SelectionError(msg)
    declared = _object(document.get("packs", {}), "selection 'packs'")
    verdicts = {rule_id: rule.default for rule_id, rule in rules.items()}
    known = {rule.pack for rule in rules.values()}
    if absent := sorted(set(declared) - known):
        msg = f"selection names pack(s) {absent}; this build carries {sorted(known)}"
        raise SelectionError(msg)
    for pack in known & set(declared):
        members = {rule_id: rule for rule_id, rule in rules.items() if rule.pack == pack}
        _apply_pack(pack, declared[pack], members, verdicts)
    return verdicts


def load(root: Path, rules: Mapping[str, Rule]) -> dict[str, str]:
    """The selection that governs. No file means nothing was spoken for: every rule runs at its default."""
    path = Path(root) / FILENAME
    if not path.is_file():
        return {rule_id: rule.default for rule_id, rule in rules.items()}
    return parse(path.read_text(encoding="utf-8"), rules)

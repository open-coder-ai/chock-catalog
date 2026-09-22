"""What each rule does when it fires. A selection sets verdicts; it never defines a rule."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from chock_security.decision import DENY, VERDICTS
from chock_security.pack import Rule

SCHEMA_VERSION = 1

FILENAME = ".chock/security.json"

#: The plugin tier's own selection, for an agent installed where no repository governs.
USER_FILENAME = ".chock/security.json"

#: The whole file, and the whole of a pack. Anything else is a rule becoming configuration.
_TOP_KEYS = frozenset({"version", "packs"})
_PACK_KEYS = frozenset({"verdict", "rules"})

#: A rule nobody spoke about enforces. Silence is never a way to switch enforcement off.
DEFAULT = DENY


class SelectionError(Exception):
    """A selection that does not say, unambiguously, what each known rule does."""


def _require_keys(document: dict, allowed: frozenset[str], where: str) -> None:
    if unknown := sorted(set(document) - allowed):
        msg = f"{where} has unknown key(s) {unknown}; only {sorted(allowed)} are read"
        raise SelectionError(msg)


def _packs_of(rules: Mapping[str, Rule]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = {}
    for rule in rules.values():
        grouped.setdefault(rule.pack, set()).add(rule.id)
    return grouped


def _verdict(where: str, subject: str, value: object) -> str:
    if value not in VERDICTS:
        msg = (
            f"{where} sets {subject} to {value!r}; a verdict is one of {list(VERDICTS)}. A "
            "selection says what rules that already exist do, and cannot carry patterns, "
            "severities or paths, because a rule definable in JSON is a program in disguise."
        )
        raise SelectionError(msg)
    return str(value)


def _verdicts_in(pack: str, ids: set[str], declared: object) -> dict[str, str]:
    """A pack or rule the file omits enforces: an upgrade's rule runs until spoken for."""
    where = f"pack {pack!r}"
    if declared is None:
        return dict.fromkeys(ids, DEFAULT)
    if not isinstance(declared, dict):
        got = type(declared).__name__
        msg = f"{where} must be an object with keys {sorted(_PACK_KEYS)}, got {got}"
        raise SelectionError(msg)
    _require_keys(declared, _PACK_KEYS, where)
    if "verdict" in declared:
        return dict.fromkeys(ids, _verdict(where, "'verdict'", declared["verdict"]))
    spoken = declared.get("rules") or {}
    if not isinstance(spoken, dict):
        msg = f"{where} 'rules' must be an object of rule id -> {list(VERDICTS)}"
        raise SelectionError(msg)
    if absent := sorted(set(spoken) - ids):
        msg = f"{where} names rule(s) it does not contain: {absent}"
        raise SelectionError(msg)
    return {
        rule_id: _verdict(where, repr(rule_id), spoken[rule_id]) if rule_id in spoken else DEFAULT
        for rule_id in ids
    }


def _document(raw: str) -> dict:
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = f"selection is not valid JSON: {exc}"
        raise SelectionError(msg) from exc
    if not isinstance(document, dict):
        got = type(document).__name__
        msg = f"selection must be an object with keys {sorted(_TOP_KEYS)}, got {got}"
        raise SelectionError(msg)
    _require_keys(document, _TOP_KEYS, "selection")
    if document.get("version") != SCHEMA_VERSION:
        msg = f"selection version must be {SCHEMA_VERSION}, got {document.get('version')!r}"
        raise SelectionError(msg)
    return document


def parse(raw: str, rules: Mapping[str, Rule]) -> dict[str, str]:
    """Every known rule's verdict, or SelectionError saying exactly what is wrong."""
    document = _document(raw)
    declared = document.get("packs") or {}
    if not isinstance(declared, dict):
        msg = "selection 'packs' must be an object of pack name -> {verdict, rules}"
        raise SelectionError(msg)
    packs = _packs_of(rules)
    if absent := sorted(set(declared) - set(packs)):
        msg = f"selection names pack(s) this build does not carry: {absent}"
        raise SelectionError(msg)
    verdicts: dict[str, str] = {}
    for pack, ids in packs.items():
        verdicts |= _verdicts_in(pack, ids, declared.get(pack))
    return verdicts


def render(rules: Mapping[str, Rule]) -> str:
    """The exhaustive selection, every rule enforcing: what install writes, upgrade reconciles."""
    packs = {
        pack: {"rules": dict.fromkeys(sorted(ids), DEFAULT)}
        for pack, ids in sorted(_packs_of(rules).items())
    }
    return json.dumps({"version": SCHEMA_VERSION, "packs": packs}, indent=2) + "\n"


def user_path() -> Path:
    """The user-level selection, which governs only where no repository has one of its own."""
    return Path.home() / USER_FILENAME


def source(root: Path) -> Path | None:
    """The file that governs here, or None when nothing was spoken for.

    A repository's own selection always wins: it is committed, it shows in a diff, and
    `check-baseline` holds it to its base branch. The user-level file is the plugin tier's
    floor for work outside such a repository, never a way to soften one from a home directory.
    """
    repo = Path(root) / FILENAME
    if repo.is_file():
        return repo
    user = user_path()
    return user if user.is_file() else None


def load(root: Path, rules: Mapping[str, Rule]) -> dict[str, str]:
    """The selection that governs. No file means nothing was spoken for, so every rule enforces."""
    path = source(root)
    if path is None:
        return dict.fromkeys(rules, DEFAULT)
    return parse(path.read_text(encoding="utf-8"), rules)

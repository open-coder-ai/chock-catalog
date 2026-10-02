"""The guard and mitigation shape table: regex per family, validated and compiled once."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from chock_scan import data_table

GROUPS = frozenset({"check", "registration", "sanitize", "path", "tls"})
TRIGGERS = frozenset({"removed", "removed-or-added", "replaced-by-weak"})
ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
MAX_PATTERN = 1500
GUARD_KEYS = frozenset({"id", "group", "label", "pattern"})
MITIGATION_KEYS = frozenset({"id", "label", "trigger", "removed", "kept", "weak", "fix"})
REQUIRED = frozenset({"id", "label", "trigger", "removed", "fix"})


@dataclass(frozen=True)
class Guard:
    id: str
    group: str
    label: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Mitigation:
    id: str
    label: str
    trigger: str
    removed: re.Pattern[str]
    kept: re.Pattern[str]
    weak: re.Pattern[str] | None
    fix: str


@dataclass(frozen=True)
class Shapes:
    guards: tuple[Guard, ...]
    mitigations: tuple[Mitigation, ...]


def _pattern(where: str, value: object) -> list[str]:
    if not isinstance(value, str) or not 0 < len(value) <= MAX_PATTERN:
        return [f"{where} must be a regex of 1..{MAX_PATTERN} characters"]
    try:
        compiled = re.compile(value)
    except re.error as exc:
        return [f"{where} does not compile ({exc})"]
    return [f"{where} matches an empty line"] if compiled.search("") else []


def _text(where: str, value: object) -> list[str]:
    return [] if isinstance(value, str) and value.strip() else [f"{where} must be non-empty text"]


def _entry(kind: str, row: object, allowed: frozenset[str], required: frozenset[str]) -> list[str]:
    if not isinstance(row, dict):
        return [f"{kind} entries must be objects"]
    name = f"{kind} {row.get('id')!r}"
    if unknown := sorted(set(row) - allowed):
        return [f"{name} has unknown keys: {', '.join(unknown)}"]
    if missing := sorted(required - set(row)):
        return [f"{name} lacks keys: {', '.join(missing)}"]
    out = [] if isinstance(row["id"], str) and ID.fullmatch(row["id"]) else [f"{name} id must be kebab-case"]
    return out + _text(f"{name} label", row["label"])


def _problems(doc: dict) -> list[str]:
    out: list[str] = []
    ids: list[object] = []
    for kind, key, allowed, required in (
        ("guard", "guards", GUARD_KEYS, GUARD_KEYS),
        ("mitigation", "mitigations", MITIGATION_KEYS, REQUIRED),
    ):
        rows = doc[key]
        if not isinstance(rows, list) or not rows:
            out.append(f"{key} must be a non-empty list")
            continue
        for row in rows:
            found = _entry(kind, row, allowed, required)
            out += found
            if found:
                continue
            ids.append(row["id"])
            name = f"{kind} {row['id']!r}"
            if kind == "guard":
                out += _pattern(f"{name} pattern", row["pattern"])
                out += [] if row["group"] in GROUPS else [f"{name} group must be one of {', '.join(sorted(GROUPS))}"]
                continue
            out += _text(f"{name} fix", row["fix"])
            out += (
                [] if row["trigger"] in TRIGGERS else [f"{name} trigger must be one of {', '.join(sorted(TRIGGERS))}"]
            )
            for field in ("removed", "kept", "weak"):
                if field in row:
                    out += _pattern(f"{name} {field}", row[field])
            if (row["trigger"] != "removed") != ("weak" in row):
                out.append(f"{name} needs a weak pattern exactly when its trigger is not 'removed'")
    if len(ids) != len(set(ids)):
        out.append("guard and mitigation ids must be unique")
    return out


def load(path: str | os.PathLike[str]) -> Shapes:
    """The validated, compiled table; raises data_table.TableError."""
    doc = data_table.load(path, kind="curated", schema=1, keys=("guards", "mitigations"), check=_problems)
    guards = tuple(Guard(g["id"], g["group"], g["label"], re.compile(g["pattern"])) for g in doc["guards"])
    mitigations = tuple(
        Mitigation(
            m["id"],
            m["label"],
            m["trigger"],
            re.compile(m["removed"]),
            re.compile(m.get("kept", m["removed"])),
            re.compile(m["weak"]) if "weak" in m else None,
            m["fix"],
        )
        for m in doc["mitigations"]
    )
    return Shapes(guards, mitigations)

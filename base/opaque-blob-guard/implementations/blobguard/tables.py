"""The policy's data tables (implementations/data/*.json), loaded and checked once per process."""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path
from typing import NamedTuple

from chock_scan import data_table

DATA = Path(__file__).resolve().parent.parent / "data"
SHA256 = re.compile(r"[0-9a-f]{64}")


class Sig(NamedTuple):
    """One signature: every (offset, bytes) pair must match; `non_text_within` also wants a non-text byte."""

    name: str
    label: str
    at: tuple[tuple[int, bytes], ...]
    non_text_within: int


class Tables(NamedTuple):
    dirs: frozenset[str]
    gradle_dir: str
    text_names: frozenset[str]
    text_suffixes: tuple[str, ...]
    allowlist: str
    magic: tuple[Sig, ...]
    media: tuple[Sig, ...]
    entropy: dict
    patterns: tuple[tuple[str, str, re.Pattern[str]], ...]
    known_wrappers: frozenset[str]


def _need(ok: bool, what: str) -> None:  # noqa: FBT001
    if not ok:
        raise ValueError(what)


def _strings(doc: dict, *keys: str) -> None:
    for key in keys:
        value = doc[key]
        ok = isinstance(value, list) and value and all(isinstance(v, str) and v for v in value)
        _need(bool(ok), f"{key} must be a non-empty list of non-empty strings")


def _scope(doc: dict) -> list[str]:
    _strings(doc, "dirs", "text_names", "text_suffixes")
    _need(all(isinstance(doc[k], str) and doc[k] for k in ("gradle_wrapper", "allowlist")), "paths must be strings")
    return []


def _sigs(rows: list[dict]) -> tuple[Sig, ...]:
    """Signatures from table rows; a malformed row raises (the loader reports it as a table problem)."""
    _need(isinstance(rows, list) and bool(rows), "a signature list must not be empty")
    sigs = tuple(
        Sig(
            row["name"],
            row.get("label", row["name"]),
            tuple((_offset(off), bytes.fromhex(hx)) for off, hx in row["at"]),
            row.get("non_text_within", 0),
        )
        for row in rows
    )
    _need(all(s.at and all(part for _, part in s.at) for s in sigs), "a signature needs at least one byte")
    return sigs


def _offset(value: object) -> int:
    _need(type(value) is int and value >= 0, "offsets are non-negative integers")
    return value  # type: ignore[return-value]


def _magic(doc: dict) -> list[str]:
    _sigs(doc["magic"])
    _sigs(doc["media"])
    ent = doc["entropy"]
    _need(set(ent) == {"min_size", "window", "min_tail", "bits_per_byte"}, "entropy keys are fixed")
    _need(all(type(ent[k]) is int and ent[k] > 0 for k in ("min_size", "window", "min_tail")), "entropy sizes")
    _need(isinstance(ent["bits_per_byte"], (int, float)) and 0 < ent["bits_per_byte"] <= 8, "entropy bits")  # noqa: PLR2004
    return []


def _patterns(doc: dict) -> list[str]:
    _need(isinstance(doc["patterns"], list) and bool(doc["patterns"]), "patterns must not be empty")
    for row in doc["patterns"]:
        try:
            re.compile(row["regex"])
        except re.error as exc:
            raise ValueError(str(exc)) from None
        _need(isinstance(row["id"], str) and isinstance(row["why"], str), "a pattern needs an id and a reason")
    return []


def _gradle(doc: dict) -> list[str]:
    known = doc["known_wrapper_sha256"]
    _need(isinstance(known, list) and all(isinstance(h, str) and SHA256.fullmatch(h) for h in known), "sha256 list")
    return []


def _table(name: str, keys: list[str], check: object) -> dict:
    return data_table.load(DATA / name, kind="curated", schema=1, keys=keys, check=check)  # type: ignore[arg-type]


@cache
def load() -> Tables:
    """Every table, validated; a bad or missing one raises TableError and the gate refuses to judge."""
    scope = _table("scope.json", ["dirs", "gradle_wrapper", "text_names", "text_suffixes", "allowlist"], _scope)
    magic = _table("magic.json", ["magic", "media", "entropy"], _magic)
    rules = _table("textrules.json", ["patterns"], _patterns)
    gradle = _table("gradle.json", ["known_wrapper_sha256"], _gradle)
    return Tables(
        dirs=frozenset(scope["dirs"]),
        gradle_dir=scope["gradle_wrapper"],
        text_names=frozenset(scope["text_names"]),
        text_suffixes=tuple(scope["text_suffixes"]),
        allowlist=scope["allowlist"],
        magic=_sigs(magic["magic"]),
        media=_sigs(magic["media"]),
        entropy=magic["entropy"],
        patterns=tuple((p["id"], p["why"], re.compile(p["regex"])) for p in rules["patterns"]),
        known_wrappers=frozenset(gradle["known_wrapper_sha256"]),
    )

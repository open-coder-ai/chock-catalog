"""The hardening-flag table (EP12 data table) and the match of its entries against logical lines."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from chock_scan import data_table

TABLE = Path(__file__).resolve().parent.parent / "data" / "flags.json"
TIERS = ("block", "ask")
LANGS = frozenset({"c", "go", "rust", "kernel"})
FIELDS = frozenset({"id", "tier", "langs", "pattern", "what"})
#: Rows a table edit may not drop: the gate refuses a table without them rather than judge less.
REQUIRED = frozenset(
    {
        "no-stack-protector",
        "fortify-source-zero",
        "no-pie",
        "execstack",
        "norelro",
        "kernel-stackprotector-off",
        "kernel-kaslr-off",
    }
)
ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
HEADER = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*$")


@dataclass(frozen=True)
class Entry:
    id: str
    tier: str
    langs: frozenset[str]
    pattern: re.Pattern[str]
    what: str
    section: re.Pattern[str] | None


def _problems(doc: dict) -> list[str]:
    """Everything wrong with the payload: a missing or odd field, a repeated id, a pattern that cannot run."""
    entries, seen, out = doc["entries"], set(), []
    if not isinstance(entries, list) or not entries:
        return ["entries must be a non-empty list"]
    for n, item in enumerate(entries):
        name = f"entries[{n}]"
        if not isinstance(item, dict) or not FIELDS <= item.keys() <= FIELDS | {"section"}:
            out.append(f"{name}: fields must be {sorted(FIELDS)} and optionally section")
            continue
        if not (isinstance(item["id"], str) and ID.fullmatch(item["id"])) or item["id"] in seen:
            out.append(f"{name}: id must be a unique kebab-case string")
        seen.add(item["id"])
        if item["tier"] not in TIERS:
            out.append(f"{name}: tier must be one of {TIERS}")
        langs = item["langs"]
        if not (isinstance(langs, list) and langs and set(langs) <= LANGS):
            out.append(f"{name}: langs must be a non-empty list from {sorted(LANGS)}")
        if not (isinstance(item["what"], str) and item["what"].strip()):
            out.append(f"{name}: what must say what the setting weakens")
        out.extend(_regex_problems(name, item))
    if missing := sorted(REQUIRED - seen):
        out.append(f"required entries missing: {', '.join(missing)}")
    return out


def _regex_problems(name: str, item: dict) -> list[str]:
    out = []
    for field in ("pattern", "section"):
        if field not in item:
            continue
        try:
            compiled = re.compile(item[field])
        except (re.error, TypeError) as exc:
            out.append(f"{name}: {field} does not compile: {exc}")
            continue
        if compiled.search(""):
            out.append(f"{name}: {field} matches the empty string")
    return out


def load(path: Path = TABLE) -> list[Entry]:
    """The table's entries; a table that fails its checks raises data_table.TableError (the gate then refuses)."""
    doc = data_table.load(path, kind="curated", schema=1, keys=["entries"], check=_problems)
    return [
        Entry(
            id=e["id"],
            tier=e["tier"],
            langs=frozenset(e["langs"]),
            pattern=re.compile(e["pattern"]),
            what=e["what"],
            section=re.compile(e["section"]) if "section" in e else None,
        )
        for e in doc["entries"]
    ]


def section_of(line: str, current: str) -> str:
    """The TOML table a line opens (quotes and spaces dropped), or the table already open."""
    if m := HEADER.match(line):
        return re.sub(r"[\s\"']", "", m.group(1))
    return current


def hits(entries: list[Entry], langs: frozenset[str], text: str, section: str) -> Iterator[tuple[Entry, int]]:
    """Each entry that applies to a file of these languages and matches the line, with the match offset."""
    for entry in entries:
        if not entry.langs & langs:
            continue
        if entry.section and not entry.section.search(section):
            continue
        for m in entry.pattern.finditer(text):
            yield entry, m.start()

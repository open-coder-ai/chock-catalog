"""The curated tables the rules read (denied options, environment keys, version floors), loaded once with the D7 loader."""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path

from chock_scan import data_table

DATA = Path(__file__).resolve().parent.parent / "data"
DENYLIST_KEYS = ("options", "option_values", "env_keys")
ECOSYSTEMS = frozenset({"npm", "pypi"})


def _words(doc: dict) -> list[str]:
    return [f"{key} must be a list of non-empty strings" for key in DENYLIST_KEYS if not _all_text(doc[key])]


def _all_text(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item for item in value)


def _floors(doc: dict) -> list[str]:
    rows = doc["floors"]
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return ["floors must be a list of objects"]
    shape = {"package", "ecosystem", "min"}
    return [
        "each floor needs exactly package, ecosystem (npm or pypi) and min as text"
        for row in rows
        if row.keys() != shape
        or row["ecosystem"] not in ECOSYSTEMS
        or not all(isinstance(v, str) for v in row.values())
    ]


@cache
def denylist() -> dict[str, frozenset[str]]:
    """Lowercased `options`, `option_values` (flag=value) and `env_keys` (upper case); TableError when the table is bad."""
    doc = data_table.load(DATA / "mcp-option-denylist.json", kind="curated", schema=1, keys=DENYLIST_KEYS, check=_words)
    return {
        key: frozenset(item.lower() if key != "env_keys" else item.upper() for item in doc[key])
        for key in DENYLIST_KEYS
    }


@cache
def floors() -> dict[tuple[str, str], str]:
    """{(ecosystem, package): minimum version} from the version-floor table."""
    doc = data_table.load(DATA / "mcp-version-floors.json", kind="curated", schema=1, keys=("floors",), check=_floors)
    return {(row["ecosystem"], re.sub(r"[-_.]+", "-", row["package"].lower())): row["min"] for row in doc["floors"]}

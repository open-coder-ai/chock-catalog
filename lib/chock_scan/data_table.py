"""Load a curated data table (EP12, decision D7): a dated, sourced, schema-checked JSON object, or a TableError.

Every table is one JSON object carrying the envelope `schema` (an integer version), `kind` (what
the freshness limit is), `as_of` (the ISO date it was last checked against its sources) and
`source` (an https URL or a citation, or an object of id to either), beside its payload keys.
The caller names the kind, schema version and payload keys it expects, so a data edit cannot
re-label an IOC table as a longer-lived kind, add a key a consumer ignores, or pass as another
version. Nothing here returns an empty table for a broken one: every refusal raises.

Freshness is separate from loading on purpose: a stale table still holds what it held, so a
guard keeps using it; the catalog's CI fails on it (tools/check_data_tables.py).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from collections import Counter
from collections.abc import Callable, Iterable

from .safe_read import UnreadableError, read_text

#: D7: days after `as_of` on which a table of each kind fails the freshness check.
KINDS = {"ioc": 120, "top-n": 365, "curated": 365}
ENVELOPE = frozenset({"schema", "kind", "as_of", "source"})
LIMIT = 1 << 23
MAX_DEPTH = 32
MAX_SOURCE = 500
#: An as_of before this is a typo, not a snapshot this catalog took.
EPOCH = dt.date(2020, 1, 1)
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
URL = re.compile(r"https://[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?:[/?#]\S*)?")
SOURCE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
WORD = re.compile(r"[A-Za-z]{3}")

Check = Callable[[dict], Iterable[str]]


class TableError(ValueError):
    """The table cannot be used; `problems` names every reason found."""

    def __init__(self, name: str, problems: list[str]) -> None:
        self.name = name
        self.problems = list(problems)
        super().__init__(f"{name}: " + "; ".join(self.problems))


class StaleError(TableError):
    """The table is valid but past its kind's freshness limit, or dated in the future."""


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    """An object's members; a repeated key raises (json would keep the last, hiding the first)."""
    out = dict(pairs)
    if len(out) != len(pairs):
        counts = Counter(k for k, _ in pairs)
        msg = "duplicate keys: " + ", ".join(sorted(repr(k) for k, n in counts.items() if n > 1)[:10])
        raise ValueError(msg)
    return out


def _constant(name: str) -> None:
    msg = f"{name} is not JSON"
    raise ValueError(msg)


def _depth(value: dict) -> int:
    """How deeply arrays and objects nest under an object (1 for a flat one), walked without recursion."""
    deepest = 0
    stack: list[tuple[dict | list, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        deepest = max(deepest, depth)
        children = node.values() if isinstance(node, dict) else node
        stack += [(child, depth + 1) for child in children if isinstance(child, dict | list)]
    return deepest


def parse(text: str, name: str = "<table>") -> dict:
    """One JSON object: duplicate keys, NaN/Infinity, nesting past MAX_DEPTH and anything else raise TableError."""
    try:
        doc = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except RecursionError:
        raise TableError(name, [f"nested deeper than {MAX_DEPTH}"]) from None
    except ValueError as exc:
        raise TableError(name, [f"not valid JSON ({exc})"]) from None
    if not isinstance(doc, dict):
        raise TableError(name, ["the table must be a JSON object"])
    if _depth(doc) > MAX_DEPTH:
        raise TableError(name, [f"nested deeper than {MAX_DEPTH}"])
    return doc


def _source_text(where: str, value: object) -> list[str]:
    if not isinstance(value, str) or not 0 < len(value) <= MAX_SOURCE or not value.isprintable():
        return [f"{where} must be 1..{MAX_SOURCE} printable characters"]
    if value.lower().startswith("http"):
        return [] if URL.fullmatch(value) else [f"{where} must be an https:// URL with a host and no spaces"]
    return [] if WORD.search(value) else [f"{where} must be an https:// URL or a citation in words"]


def _source(value: object) -> list[str]:
    if not isinstance(value, dict):
        return _source_text("source", value)
    if not value:
        return ["source must not be an empty object"]
    out = [f"source id '{k}' must be kebab-case" for k in value if not SOURCE_ID.fullmatch(k)]
    return out + [p for k, v in value.items() for p in _source_text(f"source.{k}", v)]


def as_of(doc: dict) -> dt.date | None:
    """The table's as_of date, or None when it is not a YYYY-MM-DD date on or after EPOCH."""
    value = doc.get("as_of")
    if not isinstance(value, str) or not DATE.fullmatch(value):
        return None
    try:
        date = dt.date.fromisoformat(value)
    except ValueError:
        return None
    return date if date >= EPOCH else None


def envelope_problems(doc: dict) -> list[str]:
    """Every reason the envelope (schema, kind, as_of, source) is unusable; empty when it is valid."""
    if missing := sorted(ENVELOPE - doc.keys()):
        return [f"missing envelope keys: {', '.join(missing)}"]
    out = [] if type(doc["schema"]) is int and doc["schema"] >= 1 else ["schema must be an integer of 1 or more"]
    if not isinstance(doc["kind"], str) or doc["kind"] not in KINDS:
        out.append(f"kind must be one of {', '.join(sorted(KINDS))}")
    if as_of(doc) is None:
        out.append(f"as_of must be a YYYY-MM-DD date on or after {EPOCH}")
    return out + _source(doc["source"])


def read(path: str | os.PathLike[str], limit: int = LIMIT) -> dict:
    """A table file parsed and its envelope checked (payload unchecked: that is the consumer's `load`)."""
    name = os.fsdecode(path)
    try:
        doc = parse(read_text(path, limit), name)
    except UnreadableError as exc:
        raise TableError(name, [f"unreadable ({exc})"]) from None
    if found := envelope_problems(doc):
        raise TableError(name, found)
    return doc


def load(
    path: str | os.PathLike[str],
    *,
    kind: str,
    schema: int,
    keys: Iterable[str],
    check: Check | None = None,
) -> dict:
    """The validated table; raises TableError naming every problem found.

    `keys` is the exact set of payload keys (beside the envelope); `check`, when given, returns
    every problem in the payload and runs only once the keys are right; a check that raises
    LookupError, TypeError, ValueError or AttributeError on a malformed payload becomes a TableError.
    ValueError (not TableError) means a caller error: an unknown kind, a non-integer schema, or
    payload keys that reuse an envelope key.
    """
    if kind not in KINDS:
        msg = f"kind must be one of {', '.join(sorted(KINDS))}, not {kind!r}"
        raise ValueError(msg)
    if type(schema) is not int:
        msg = f"schema must be an int, not {schema!r}"
        raise ValueError(msg)
    want = frozenset(keys)
    if clash := sorted(want & ENVELOPE):
        msg = f"payload keys must not be envelope keys: {', '.join(clash)}"
        raise ValueError(msg)
    doc = read(path)
    name = os.fsdecode(path)
    out = [] if doc["kind"] == kind else [f"kind is {doc['kind']}, expected {kind}"]
    if doc["schema"] != schema:
        out.append(f"schema is {doc['schema']}, expected {schema}")
    if missing := sorted(want - doc.keys()):
        out.append(f"missing keys: {', '.join(missing)}")
    if unknown := sorted(doc.keys() - want - ENVELOPE):
        out.append(f"unknown keys: {', '.join(map(repr, unknown))}")
    if not out and check is not None:
        out = _checked(check, doc)
    if out:
        raise TableError(name, out)
    return doc


def _checked(check: Check, doc: dict) -> list[str]:
    try:
        found = check(doc)
        return [found] if isinstance(found, str) else [str(p) for p in found]
    except (LookupError, TypeError, ValueError, AttributeError) as exc:
        return [f"payload check failed: {type(exc).__name__}: {exc}"]


def staleness(doc: dict, today: dt.date) -> list[str]:
    """Why a table with a valid envelope is not fresh on `today`; empty when it is."""
    if isinstance(today, dt.datetime) or not isinstance(today, dt.date):
        msg = f"today must be a datetime.date, not {type(today).__name__}"
        raise TypeError(msg)
    if found := envelope_problems(doc):
        return found
    date = dt.date.fromisoformat(doc["as_of"])
    limit = KINDS[doc["kind"]]
    if date > today:
        return [f"as_of {date} is after today ({today})"]
    if (age := (today - date).days) >= limit:
        return [f"as_of {date} is {age} days old; a {doc['kind']} table must be re-checked within {limit} days"]
    return []


def check_fresh(doc: dict, today: dt.date, name: str = "<table>") -> None:
    """Raise StaleError when the table is not fresh on `today` (see `staleness`)."""
    if found := staleness(doc, today):
        raise StaleError(name, found)

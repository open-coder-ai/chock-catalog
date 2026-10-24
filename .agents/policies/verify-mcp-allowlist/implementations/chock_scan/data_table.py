"""Load a curated data table (EP12, decision D7): a dated, sourced, schema-checked JSON object, or a TableError.

Every table is one JSON object carrying the envelope `schema` (an integer version), `kind` (what
the freshness limit is), `as_of` (the ISO date it was last checked against its sources) and
`source` (an https URL or a citation, or an object of id to either), beside its payload keys.
The caller names the kind, schema version and payload keys it expects, so a data edit cannot
re-label an IOC table as a longer-lived kind, add a key a consumer ignores, or pass as another
version. Nothing here returns an empty table for a broken one: every refusal raises.

A table is a regular file named `*.json` directly in a folder named `data`, neither of them a
symlink and its path holding no `..`: what tools/check_data_tables.py finds. Folders above `data`
are not resolved here (an adopter's checkout may sit under a symlink); the catalog's CI instead
reports any symlinked folder that leads outside what it scans, so every table a shipped guard
loads is one CI judges for freshness. Sources are text, never fetched: every `://` in one must
follow a standalone `https`, which is not every string a browser might follow (`javascript:`,
`//host`, look-alike letters pass). Duplicate keys are compared exactly as decoded: keys that
differ only by case, Unicode normalisation or invisible characters are distinct, so a consumer
keyed by names normalises them itself.

Freshness is separate from loading on purpose: a stale table still holds what it held, so a
guard keeps using it; the catalog's CI fails on it (tools/check_data_tables.py).
"""

from __future__ import annotations

import datetime as dt
import json
import math
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
SHOW = 80
#: An as_of before this is a typo, not a snapshot this catalog took.
EPOCH = dt.date(2020, 1, 1)
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
URL = re.compile(r"https://[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?:[/?#]\S*)?")
#: Characters a URL scheme may hold: one of them right before `https://` makes it another scheme.
SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")
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
        msg = "duplicate keys: " + ", ".join(sorted(_show(k) for k, n in counts.items() if n > 1)[:10])
        raise ValueError(msg)
    return out


def _constant(name: str) -> None:
    msg = f"{name} is not JSON"
    raise ValueError(msg)


def _float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        msg = f"{text[:20]} overflows to {value}"
        raise ValueError(msg)
    return value


def _show(value: object) -> str:
    """A key as it may appear in a message: escaped, and cut to SHOW characters."""
    shown = repr(value)
    return shown if len(shown) <= SHOW else shown[: SHOW - 3] + "..."


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
    """One JSON object: duplicate keys, NaN/Infinity (or a number that overflows to it), nesting past MAX_DEPTH
    and anything else that is not plain JSON raise TableError."""
    try:
        doc = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
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
    if value != value.strip() or not _https_only(value):
        return [f"{where} must have no outer spaces, and no URL scheme but https://"]
    if value.lower().startswith("http"):
        return [] if URL.fullmatch(value) else [f"{where} must be an https:// URL with a host and no spaces"]
    return [] if WORD.search(value) else [f"{where} must be an https:// URL or a citation in words"]


def _https_only(value: str) -> bool:
    """Every `://` follows `https`, itself not the tail of a longer scheme; linear in the text."""
    at = value.find("://")
    while at != -1:
        start = at - len("https")
        if start < 0 or value[start:at] != "https" or (start and value[start - 1] in SCHEME_CHARS):
            return False
        at = value.find("://", at + 3)
    return True


def _source(value: object) -> list[str]:
    if not isinstance(value, dict):
        return _source_text("source", value)
    if not value:
        return ["source must not be an empty object"]
    if bad := [k for k in value if not SOURCE_ID.fullmatch(k)]:
        return [f"source id {_show(k)} must be kebab-case" for k in bad[:10]]
    return [p for k, v in value.items() for p in _source_text(f"source.{k}", v)]


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


def path_problems(path: str | os.PathLike[str]) -> list[str]:
    """Why `path` is not where a table may be: `*.json` directly in `data/`, neither a symlink, no `..`."""
    name = os.fsdecode(path)
    folder = os.path.dirname(name)
    if ".." in name.replace(os.sep, "/").split("/"):
        return ["a table path must not hold .."]
    if not name.endswith(".json") or os.path.basename(folder) != "data":
        return ["a table must be a *.json file directly in a folder named data"]
    if os.path.islink(name) or os.path.islink(folder):
        return ["a table and its data folder must not be symlinks"]
    return []


def read(path: str | os.PathLike[str], limit: int = LIMIT) -> dict:
    """A table file, its place and its envelope checked. The kind and payload are not: a guard uses `load`."""
    name = os.fsdecode(path)
    if found := path_problems(path):
        raise TableError(name, found)
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
    LookupError, TypeError, ValueError, AttributeError, ArithmeticError or RecursionError on a
    malformed payload becomes a TableError.
    ValueError (not TableError) means a caller error: an unknown kind, a non-integer schema, or
    payload keys reusing an envelope key; TypeError, keys given as one string.
    """
    if not isinstance(kind, str) or kind not in KINDS:
        msg = f"kind must be one of {', '.join(sorted(KINDS))}, not {kind!r}"
        raise ValueError(msg)
    if type(schema) is not int:
        msg = f"schema must be an int, not {schema!r}"
        raise ValueError(msg)
    if isinstance(keys, str):
        msg = f"keys must be a collection of key names, not the string {keys!r}"
        raise TypeError(msg)
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
        out.append(f"unknown keys: {', '.join(map(_show, unknown[:10]))}")
    if not out and check is not None:
        out = _checked(check, doc)
    if out:
        raise TableError(name, out)
    return doc


def _checked(check: Check, doc: dict) -> list[str]:
    try:
        found = check(doc)
        return [found] if isinstance(found, str) else [str(p) for p in found]
    except (LookupError, TypeError, ValueError, AttributeError, ArithmeticError, RecursionError) as exc:
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

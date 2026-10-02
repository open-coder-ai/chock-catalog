"""EP-17 triage tables: load data/triage.json, refusing a table that is malformed, stale or looser.

The table is advisory review data (record 12 section 2): exclusions, precedents, severity to
verdict, surface rank to tier. The limits that keep an edit from loosening it live here, in code,
so the data cannot vouch for itself: its age, the confidence ceiling, the verdict and tier order,
and the floor of paths no exclusion may cover.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import posixpath
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "data" / "triage.json"
#: D7: a top-N-style table fails CI a year after it was last checked against its sources.
MAX_AGE_DAYS = 365
KEYS = frozenset(
    {"schema", "as_of", "source", "use", "verdicts", "report_min_confidence", "rank_tier", "never_excluded"}
    | {"path_exclusions", "finding_exclusions", "precedents", "not_adopted"}
)
VERDICTS = ("allow", "ask", "deny")
#: A surface rank never promotes a heuristic to block (roadmap R2): block is not a rank tier.
TIERS = ("off", "advisory", "ask")
SEVERITIES = ("low", "medium", "high")
RANKS = ("1", "2", "3", "4", "5")
CONFIDENCE_CEILING = 8
REQUIRED_NEVER_DIRS = frozenset({".agents", ".chock", ".claude", ".cursor", ".github", "implementations"})
REQUIRED_NEVER_NAMES = frozenset({"AGENTS.md", "CLAUDE.md", "SKILL.md", "manifest.yaml"})
ENTRY_KEYS = {
    "finding_exclusions": ({"id", "text", "source"}, {"unless"}),
    "precedents": ({"id", "text", "source"}, {"unless"}),
    "path_exclusions": ({"id", "dirs", "names", "text", "source"}, set()),
    "not_adopted": ({"id", "upstream", "why", "source"}, set()),
}
TEXT_FIELDS = ("text", "unless", "upstream", "why")
MAX_TEXT = 300
ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
REPO_PATH = re.compile(r"[\w.-]+/[\w.-]+:[\w./-]+")
ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class TableError(ValueError):
    """The table cannot be used; the message names every problem."""

    def __init__(self, name: str, found: list[str]) -> None:
        super().__init__(f"{name}:\n" + "\n".join(found))


def _keys(where: str, obj: dict, required: set[str] | frozenset[str], optional: set[str] = frozenset()) -> list[str]:
    out = []
    if missing := sorted(required - obj.keys()):
        out.append(f"{where}missing keys: {', '.join(missing)}")
    if unknown := sorted(obj.keys() - required - optional):
        out.append(f"{where}unknown keys: {', '.join(unknown)}")
    return out


def _as_of(doc: dict, today: dt.date) -> list[str]:
    value = doc["as_of"]
    bad = ["as_of must be an ISO date (YYYY-MM-DD)"]
    if not isinstance(value, str) or not ISO_DATE.fullmatch(value):
        return bad
    try:
        as_of = dt.date.fromisoformat(value)
    except ValueError:
        return bad
    if as_of > today:
        return [f"as_of {value} is in the future"]
    if (today - as_of).days > MAX_AGE_DAYS:
        return [f"as_of {value} is older than {MAX_AGE_DAYS} days: re-review the table against its sources"]
    return []


def _source(doc: dict) -> list[str]:
    source = doc["source"]
    if not isinstance(source, dict) or not source:
        return ["source must be a non-empty object of id to URL or repo path"]
    good = [
        isinstance(v, str) and (v.startswith("https://") or (REPO_PATH.fullmatch(v) and ".." not in v))
        for v in source.values()
    ]
    return [] if all(good) else ["source values must be https:// URLs or owner/repo:path references"]


def _ordered(name: str, mapping: object, keys: tuple[str, ...], scale: tuple[str, ...], what: str) -> list[str]:
    if not isinstance(mapping, dict) or set(mapping) != set(keys):
        return [f"{name} must map exactly {', '.join(sorted(keys))}"]
    if bad := [f"{name}.{k} must be one of {', '.join(sorted(scale))}" for k in keys if mapping[k] not in scale]:
        return bad
    levels = [scale.index(mapping[k]) for k in keys]
    return [] if levels == sorted(levels) else [f"{name} must not loosen as {what} rises"]


def _verdicts(doc: dict) -> list[str]:
    out = _ordered("verdicts", doc["verdicts"], SEVERITIES, VERDICTS, "severity")
    if not out and doc["verdicts"]["high"] != "deny":
        out.append("verdicts.high must be deny")
    return out


def _confidence(doc: dict) -> list[str]:
    value = doc["report_min_confidence"]
    if type(value) is int and 1 <= value <= CONFIDENCE_CEILING:
        return []
    return [f"report_min_confidence must be an integer 1..{CONFIDENCE_CEILING} (raising it hides findings)"]


def _strings(where: str, value: object) -> list[str]:
    ok = isinstance(value, list) and all(isinstance(v, str) and v for v in value)
    return [] if ok else [f"{where} must be a list of strings"]


def _never(doc: dict) -> list[str]:
    never = doc["never_excluded"]
    if not isinstance(never, dict) or set(never) != {"dirs", "names"}:
        return ["never_excluded must have exactly dirs, names"]
    if out := _strings("never_excluded.dirs", never["dirs"]) + _strings("never_excluded.names", never["names"]):
        return out
    kept = set(never["dirs"]) | set(never["names"])
    return [f"never_excluded must keep {v}" for v in sorted((REQUIRED_NEVER_DIRS | REQUIRED_NEVER_NAMES) - kept)]


def _path_entry(where: str, entry: dict, never: dict) -> list[str]:
    out = _strings(f"{where}: dirs", entry["dirs"]) + _strings(f"{where}: names", entry["names"])
    if out:
        return out
    if not entry["dirs"] and not entry["names"]:
        return [f"{where}: needs dirs or names"]
    never_dirs = {d.casefold() for d in never.get("dirs", [])}
    for d in entry["dirs"]:
        if "/" in d or "\\" in d:
            out.append(f"{where}: dirs entry '{d}' must be one path segment")
        elif d.casefold() in never_dirs:
            out.append(f"{where}: dirs entry '{d}' is never excluded")
    out += [
        f"{where}: names glob '{glob}' matches never-excluded '{name}'"
        for glob in entry["names"]
        for name in never.get("names", [])
        if fnmatch.fnmatchcase(name.casefold(), glob.casefold())
    ]
    return out


def _entry(key: str, i: int, entry: object, doc: dict) -> list[str]:
    if not isinstance(entry, dict):
        return [f"{key}[{i}] must be an object"]
    where = f"{key}.{entry.get('id', i)}"
    required, optional = ENTRY_KEYS[key]
    if out := _keys(f"{where}: ", entry, required, optional):
        return out
    if not isinstance(entry["id"], str) or not ID.fullmatch(entry["id"]):
        out.append(f"{where}: id '{entry['id']}' must be kebab-case")
    out += [
        f"{where}: {field} must be 1..{MAX_TEXT} characters"
        for field in TEXT_FIELDS
        if field in entry and not (isinstance(entry[field], str) and 0 < len(entry[field]) <= MAX_TEXT)
    ]
    if isinstance(doc["source"], dict) and entry["source"] not in doc["source"]:
        out.append(f"{where}: source '{entry['source']}' is not in source")
    if key == "path_exclusions":
        never = doc["never_excluded"] if isinstance(doc["never_excluded"], dict) else {}
        out += _path_entry(where, entry, {k: v for k, v in never.items() if isinstance(v, list)})
    return out


def _entries(doc: dict) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for key in ENTRY_KEYS:
        entries = doc[key]
        if not isinstance(entries, list) or not entries:
            out.append(f"{key} must be a non-empty list")
            continue
        for i, entry in enumerate(entries):
            out += _entry(key, i, entry, doc)
            ident = entry.get("id") if isinstance(entry, dict) else None
            if not isinstance(ident, str):
                continue
            if ident in seen:
                out.append(f"duplicate id '{ident}'")
            seen.add(ident)
    return out


def problems(doc: object, today: dt.date) -> list[str]:
    """Every reason the table is unusable; empty when it is valid on `today`."""
    if not isinstance(doc, dict):
        return ["the table must be a JSON object"]
    if out := _keys("", doc, KEYS):
        return out
    out = [] if doc["schema"] == 1 else ["schema must be 1"]
    out += _as_of(doc, today) + _source(doc)
    if not (isinstance(doc["use"], str) and doc["use"].strip()):
        out.append("use must be non-empty text")
    out += _verdicts(doc) + _confidence(doc)
    out += _ordered("rank_tier", doc["rank_tier"], RANKS, TIERS, "rank")
    return out + _never(doc) + _entries(doc)


def load(path: Path = TABLE, today: dt.date | None = None) -> dict:
    """The validated table; raises TableError naming every problem."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TableError(path.name, [f"not valid JSON: {exc}"]) from exc
    if found := problems(doc, today or dt.date.today()):
        raise TableError(path.name, found)
    return doc


def excluded(doc: dict, path: str) -> str | None:
    """The path exclusion id that drops `path` from a review report, or None if it stays in scope.

    Anything that is not a plain repo-relative path stays in scope, and never_excluded wins over
    every exclusion, compared case-insensitively so a case variant cannot slip a protected file out.
    """
    norm = posixpath.normpath(path.replace("\\", "/")) if path else ""
    if not norm or norm == "." or norm.startswith(("/", "../")) or norm == "..":
        return None
    *dirs, name = norm.split("/")
    never = doc["never_excluded"]
    if {d.casefold() for d in dirs} & {d.casefold() for d in never["dirs"]}:
        return None
    if name.casefold() in {n.casefold() for n in never["names"]}:
        return None
    for entry in doc["path_exclusions"]:
        if set(dirs) & set(entry["dirs"]) or any(fnmatch.fnmatchcase(name, g) for g in entry["names"]):
            return entry["id"]
    return None

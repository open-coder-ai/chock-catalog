"""EP-17 triage tables: load data/triage.json, refusing a table that is malformed, stale or past a floor.

The table is advisory review data (record 12 section 2). The floors live here, in code, so the
data cannot vouch for itself: its age, the confidence ceiling, the verdict and tier floors, the
paths no exclusion may cover, the widest path exclusion, and which exclusions, `unless` clauses
and not-adopted entries exist. Rewording an entry's text is not detectable here; review owns it.
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
#: (keys in rising order, scale, floors as (key, least strict value), what rises).
VERDICT_SPEC = (SEVERITIES, VERDICTS, (("high", "deny"), ("medium", "ask")), "severity")
TIER_SPEC = (RANKS, TIERS, (("5", "ask"),), "rank")
CONFIDENCE_CEILING = 8
#: Agent config, hook, instruction and policy paths (protect-agent-config's set and more), and
#: this table and its loader. A review report never drops them, whatever the data says.
NEVER_DIRS = frozenset(
    {".agents", ".chock", ".claude", ".codex", ".cursor", ".devin", ".gemini", ".git", ".github", ".githooks"}
    | {".grok", ".husky", ".junie", ".kimi-code", ".tabnine", ".vscode", ".windsurf"}
    | {"evals", "implementations", "skill", "skills"}
)
NEVER_NAMES = frozenset(
    {".aider.conf.yml", ".clinerules", ".cursorrules", ".mcp.json", ".windsurfrules", "AGENTS.md"}
    | {"AGENTS.override.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", "SKILL.md", "codex.md"}
    | {"copilot-instructions.md", "conf.py", "conftest.py", "manifest.yaml", "suite.yaml"}
    | {"triage.json", "triage_tables.py"}
)
#: The widest path exclusion: data may use a subset; anything wider is a code change.
EXCLUDABLE_DIRS = frozenset(
    {"tests", "test", "__tests__", "testdata", "docs", "__generated__", "vendor", "third_party", "node_modules"}
)
EXCLUDABLE_NAMES = frozenset(
    {"test_*.py", "*_test.py", "*_test.go", "*.test.js", "*.test.ts", "*.spec.js", "*.spec.ts", "*Test.java"}
    | {"*Tests.java", "*.pb.go", "*_pb2.py", "*_pb2_grpc.py", "*.min.js"}
)
#: Every finding exclusion and precedent that may exist, and whether it must keep its `unless`.
WITH_UNLESS = frozenset(
    {"denial-of-service", "workflow-input", "theoretical-race", "outdated-dependency", "safe-rust-memory"}
    | {"env-and-cli-trusted", "uuid-unguessable", "notebook-and-script-injection"}
)
FINDING_IDS = frozenset(
    {"denial-of-service", "generic-validation", "workflow-input", "theoretical-race", "outdated-dependency"}
    | {"safe-rust-memory", "log-spoofing", "path-only-ssrf", "regex-injection", "missing-audit-log"}
)
PRECEDENT_IDS = frozenset(
    {"env-and-cli-trusted", "uuid-unguessable", "client-side-auth", "framework-autoescape", "logging-urls"}
    | {"medium-only-if-concrete", "notebook-and-script-injection"}
)
NOT_ADOPTED_IDS = frozenset(
    {"secrets-on-disk", "user-content-in-prompts", "lack-of-hardening", "documentation-files", "open-redirect"}
)
KNOWN_IDS = {"finding_exclusions": FINDING_IDS, "precedents": PRECEDENT_IDS}
ENTRY_KEYS = {
    "finding_exclusions": ({"id", "text", "source"}, {"unless"}),
    "precedents": ({"id", "text", "source"}, {"unless"}),
    "path_exclusions": ({"id", "dirs", "names", "text", "source"}, set()),
    "not_adopted": ({"id", "upstream", "why", "source"}, set()),
}
TEXT_FIELDS = ("text", "unless", "upstream", "why")
MAX_TEXT = 300
ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
REPO_PATH = re.compile(r"[\w.-]+/[\w.-]+:[\w.-]+(?:/[\w.-]+)*")
URL = re.compile(r"https://[\w-]+(?:\.[\w-]+)+(?:/\S*)?")
ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
WORDS = re.compile(r"[A-Za-z]{3}")


class TableError(ValueError):
    """The table cannot be used; the message names every problem."""

    def __init__(self, name: str, found: list[str]) -> None:
        super().__init__(f"{name}:\n" + "\n".join(found))


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    if dupes := sorted({k for k in keys if keys.count(k) > 1}):
        raise ValueError("duplicate keys: " + ", ".join(dupes))
    return dict(pairs)


def _keys(where: str, obj: dict, required: set[str] | frozenset[str], optional: set[str] = frozenset()) -> list[str]:
    out = []
    if missing := sorted(required - obj.keys()):
        out.append(f"{where}missing keys: {', '.join(missing)}")
    if unknown := sorted(obj.keys() - required - optional):
        out.append(f"{where}unknown keys: {', '.join(unknown)}")
    return out


def _as_of(value: object, today: dt.date) -> list[str]:
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
    good = [isinstance(v, str) and bool(URL.fullmatch(v) or REPO_PATH.fullmatch(v)) for v in source.values()]
    out = [] if all(good) else ["source values must be https:// URLs or owner/repo:path references"]
    cited = {s for key in ENTRY_KEYS if isinstance(doc[key], list) for e in doc[key] for s in _cites(e)}
    return out + [f"source '{s}' is cited by no entry" for s in sorted(source.keys() - cited)]


def _cites(entry: object) -> list[str]:
    cites = entry.get("source") if isinstance(entry, dict) else None
    return [c for c in cites if isinstance(c, str)] if isinstance(cites, list) else []


def _ordered(name: str, mapping: object, spec: tuple) -> list[str]:
    keys, scale, floor, what = spec
    if not isinstance(mapping, dict) or set(mapping) != set(keys):
        return [f"{name} must map exactly {', '.join(sorted(keys))}"]
    if bad := [f"{name}.{k} must be one of {', '.join(sorted(scale))}" for k in keys if mapping[k] not in scale]:
        return bad
    levels = [scale.index(mapping[k]) for k in keys]
    out = [] if levels == sorted(levels) else [f"{name} must not loosen as {what} rises"]
    return out + [f"{name}.{k} must be at least {v}" for k, v in floor if scale.index(mapping[k]) < scale.index(v)]


def _confidence(value: object) -> list[str]:
    if type(value) is int and 1 <= value <= CONFIDENCE_CEILING:
        return []
    return [f"report_min_confidence must be an integer 1..{CONFIDENCE_CEILING} (raising it hides findings)"]


def _strings(where: str, value: object) -> list[str]:
    ok = isinstance(value, list) and all(isinstance(v, str) and v for v in value)
    return [] if ok else [f"{where} must be a list of strings"]


def _never(never: object) -> list[str]:
    if not isinstance(never, dict) or set(never) != {"dirs", "names"}:
        return ["never_excluded must have exactly dirs, names"]
    if out := _strings("never_excluded.dirs", never["dirs"]) + _strings("never_excluded.names", never["names"]):
        return out
    out = [f"never_excluded.dirs must keep {v}" for v in sorted(NEVER_DIRS - set(never["dirs"]))]
    return out + [f"never_excluded.names must keep {v}" for v in sorted(NEVER_NAMES - set(never["names"]))]


def _path_entry(where: str, entry: dict) -> list[str]:
    out = _strings(f"{where}: dirs", entry["dirs"]) + _strings(f"{where}: names", entry["names"])
    if out:
        return out
    if not entry["dirs"] and not entry["names"]:
        return [f"{where}: needs dirs or names"]
    out = [
        f"{where}: dirs entry '{d}' is wider than the code allows" for d in entry["dirs"] if d not in EXCLUDABLE_DIRS
    ]
    return out + [
        f"{where}: names glob '{g}' is wider than the code allows" for g in entry["names"] if g not in EXCLUDABLE_NAMES
    ]


def _entry(key: str, i: int, entry: object, doc: dict) -> list[str]:
    if not isinstance(entry, dict):
        return [f"{key}[{i}] must be an object"]
    where = f"{key}.{entry.get('id', i)}"
    required, optional = ENTRY_KEYS[key]
    if out := _keys(f"{where}: ", entry, required, optional):
        return out
    ident = entry["id"]
    if not isinstance(ident, str) or not ID.fullmatch(ident):
        out.append(f"{where}: id '{ident}' must be kebab-case")
    elif key in KNOWN_IDS and ident not in KNOWN_IDS[key]:
        out.append(f"{where}: not a known entry; a new exclusion or precedent is a code change")
    elif ident in WITH_UNLESS and "unless" not in entry:
        out.append(f"{where}: must keep its unless clause")
    out += [
        f"{where}: {field} must be 1..{MAX_TEXT} characters"
        for field in TEXT_FIELDS
        if field in entry and not (isinstance(entry[field], str) and 0 < len(entry[field]) <= MAX_TEXT)
    ]
    cites = entry["source"]
    if not isinstance(cites, list) or not cites or not all(isinstance(c, str) for c in cites):
        out.append(f"{where}: source must be a non-empty list of source ids")
    elif isinstance(doc["source"], dict):
        out += [f"{where}: source '{c}' is not in source" for c in cites if c not in doc["source"]]
    return out + (_path_entry(where, entry) if key == "path_exclusions" else [])


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
    return out + [f"not_adopted must keep {i}" for i in sorted(NOT_ADOPTED_IDS - seen)]


def problems(doc: object, today: dt.date) -> list[str]:
    """Every reason the table is unusable; empty when it is valid on `today`."""
    if not isinstance(doc, dict):
        return ["the table must be a JSON object"]
    if out := _keys("", doc, KEYS):
        return out
    out = [] if type(doc["schema"]) is int and doc["schema"] == 1 else ["schema must be 1"]
    out += _as_of(doc["as_of"], today) + _source(doc)
    if not (isinstance(doc["use"], str) and WORDS.search(doc["use"])):
        out.append("use must be non-empty text")
    out += _ordered("verdicts", doc["verdicts"], VERDICT_SPEC)
    out += _confidence(doc["report_min_confidence"])
    out += _ordered("rank_tier", doc["rank_tier"], TIER_SPEC)
    return out + _never(doc["never_excluded"]) + _entries(doc)


def load(path: Path = TABLE, today: dt.date | None = None) -> dict:
    """The validated table; raises TableError naming every problem, and for anything unreadable."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates)
    except (OSError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        raise TableError(path.name, [f"unreadable: {exc}"]) from exc
    if found := problems(doc, today or dt.date.today()):
        raise TableError(path.name, found)
    return doc


def _plain(path: str) -> list[str] | None:
    """The path's segments, or None when it is anything but a plain repo-relative POSIX path."""
    if not path or "\\" in path or ":" in path or path.startswith(("/", "~")):
        return None
    norm = posixpath.normpath(path)
    parts = norm.split("/")
    if norm == "." or parts[0] == ".." or any(p.endswith((".", " ")) or p.startswith("~") for p in parts):
        return None
    return parts


def excluded(doc: dict, path: str) -> str | None:
    """The path exclusion id that drops `path` from a review report, or None if it stays in scope.

    Only a plain repo-relative POSIX path can be excluded. The code floor and never_excluded win
    over every exclusion, compared case-insensitively so a case variant cannot slip a file out.
    """
    parts = _plain(path)
    if parts is None:
        return None
    *dirs, name = parts
    never_dirs = {d.casefold() for d in NEVER_DIRS | set(doc["never_excluded"]["dirs"])}
    never_names = {n.casefold() for n in NEVER_NAMES | set(doc["never_excluded"]["names"])}
    if {d.casefold() for d in dirs} & never_dirs or name.casefold() in never_names:
        return None
    for entry in doc["path_exclusions"]:
        if set(dirs) & set(entry["dirs"]) or any(fnmatch.fnmatchcase(name, g) for g in entry["names"]):
            return entry["id"]
    return None

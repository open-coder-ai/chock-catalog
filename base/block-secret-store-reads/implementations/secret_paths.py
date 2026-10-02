"""Resolve a path argument and match it against the credential-store table (stdlib only)."""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from itertools import dropwhile
from pathlib import Path
from typing import Any, NamedTuple

from chock_scan import data_table

TABLE = Path(__file__).resolve().parent / "data" / "secret_stores.json"
KEYS = ("home", "names", "templates", "absolute", "interpreters", "recursive", "dotskip", "readers", "printers")
MODES = frozenset(("operands", "pattern-first", "program-first", "sources", "archive", "dd"))
ACTIONS = frozenset(("block", "ask"))
RELATIVE = frozenset(("always", "code", "never"))
MIN_LITERAL = 2
TEXT_LIMIT = 1 << 20
_HOME = re.compile(r"(?:~[\w.-]*|\$\{?(?:HOME|USERPROFILE)\}?|%USERPROFILE%|\$env:(?:HOME|USERPROFILE))(?=/|$)", re.I)
_VAR = re.compile(r"\$(?:\{(\w+)\}|(\w+))")
_DRIVE = re.compile(r"^[A-Za-z]:(?=/)")
_ANCHOR = re.compile(
    r"^/(?:(?:mnt|cygdrive)/)?(?:[A-Za-z]/)?(?:(?:(?:usr|export)/)?(?:home|Users)/[^/]+|(?:private/)?(?:var/)?root)(?=/|$)"
)
_PROC_CWD = re.compile(r"^/proc/[^/]+/cwd/?")
_PROC_ROOT = re.compile(r"^/proc/[^/]+/(?:root|cwd)(?=/|$)")
ANCESTORS = frozenset((("/",), ("/", "home"), ("/", "Users"), ("/", "users")))
_GLOB = re.compile(r"[*?\[]")
_WORD = re.compile(r"[^\s'\"`()\[\]{},;=<>|&]+")
_DIRS = {
    "XDG_CONFIG_HOME": ".config",
    "XDG_DATA_HOME": ".local/share",
    "XDG_CACHE_HOME": ".cache",
    "APPDATA": "AppData/Roaming",
    "LOCALAPPDATA": "AppData/Local",
}
Hit = tuple[str, str]


class Entry(NamedTuple):
    """One credential location: components (casefolded, may hold globs), what stays readable, how it matches."""

    label: str
    path: tuple[str, ...]
    allow: tuple[str, ...]
    files: tuple[str, ...]
    relative: str
    action: str


class Table(NamedTuple):
    home: tuple[Entry, ...]
    names: tuple[Entry, ...]
    absolute: tuple[Entry, ...]
    templates: tuple[str, ...]
    interpreters: frozenset[str]
    recursive: dict[str, Any]
    dotskip: dict[str, list[str]]
    readers: dict[str, str]
    printers: list[dict[str, Any]]


def _problems(doc: dict) -> list[str]:
    found = [f"unknown reader mode {mode!r}" for mode in sorted(set(doc["readers"].values()) - MODES)]
    found += [] if doc["readers"] else ["readers must not be empty"]
    for item in [*doc["home"], *doc["names"], *doc["absolute"]]:
        if item.get("action", "block") not in ACTIONS:
            found.append(f"{item['id']}: action must be block or ask")
        if item.get("relative", "never") not in RELATIVE:
            found.append(f"{item['id']}: relative must be always, code or never")
    return found


def _fold(texts: Any) -> tuple[str, ...]:
    return tuple(text.casefold() for text in texts)


def _entries(items: list[dict], key: str, *, split: bool = True) -> tuple[Entry, ...]:
    return tuple(
        Entry(
            item["label"],
            _fold(path.strip("/").split("/") if split else [path]),
            _fold(item.get("allow", ())),
            _fold(item.get("files", ())),
            item.get("relative", "never"),
            item.get("action", "block"),
        )
        for item in items
        for path in item[key]
    )


def load(path: Path = TABLE) -> Table:
    """The validated table; a TableError (a guard fault, never a verdict) when it is broken."""
    doc = data_table.load(path, kind="curated", schema=1, keys=KEYS, check=_problems)
    return Table(
        _entries(doc["home"], "paths"),
        _entries(doc["names"], "patterns", split=False),
        _entries([{**item, "paths": [item["path"]]} for item in doc["absolute"]], "paths"),
        tuple(doc["templates"]),
        frozenset(doc["interpreters"]),
        doc["recursive"],
        doc["dotskip"],
        doc["readers"],
        doc["printers"],
    )


def _lookup(match: re.Match[str], env: dict[str, str]) -> str:
    name = match.group(1) or match.group(2)
    if name in _DIRS:
        return f"/home/~/{_DIRS[name]}"
    return env[name] if name in env and name not in ("HOME", "USERPROFILE") else match.group(0)


def expand(path: str, env: dict[str, str]) -> str:
    """Substitute the variables the parser saw assigned (three rounds), then a leading home form with `/home/~`."""
    for _ in range(3):
        path = _VAR.sub(lambda match: _lookup(match, env), path)
    home = _HOME.match(path)
    return "/home/~" + path[home.end() :] if home else path


def collapse(text: str) -> list[str]:
    """Path components with `.`, `..` and empty parts resolved; leading `..` of a relative path are kept."""
    parts: list[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part != "..":
            parts.append(part)
        elif parts and parts[-1] != "..":
            parts.pop()
        elif not text.startswith("/"):
            parts.append("..")
    return parts


def render(parts: tuple[str, ...]) -> str:
    """A resolved path back to text (home as `/home/~`), for joining a relative path onto it."""
    if parts[:1] == ("~",):
        return "/".join(("/home", *parts))
    return "/" + "/".join(parts[1:]) if parts[:1] == ("/",) else "/".join(parts)


def resolve(path: str, env: dict[str, str], cwd: tuple[str, ...] | None = None) -> tuple[str, ...]:
    """Components of a path: first `~` (home, however spelled), `/` (other absolute) or the first relative part."""
    text = _PROC_CWD.sub("", _DRIVE.sub("", expand(path.replace("\\", "/"), env)))
    if cwd and not text.startswith("/"):
        text = f"{render(cwd)}/{text}"
    parts = collapse(text)
    if not text.startswith("/"):
        return tuple(parts)
    flat = _PROC_ROOT.sub("", "/" + "/".join(parts))
    found = _ANCHOR.match(flat)
    if found:
        return ("~", *[part for part in flat[found.end() :].split("/") if part])
    return ("/", *[part for part in flat.split("/") if part])


def braces(word: str, cap: int = 1024) -> list[str] | None:
    """Brace alternatives of a word (`~/.{ssh,aws}` gives both); None when there are more than `cap` of them."""
    done, todo = [], [word]
    while todo:
        if len(done) + len(todo) > cap:
            return None
        item = todo.pop()
        found = re.search(r"\{([^{}]*,[^{}]*)\}", item)
        if found is None:
            done.append(item)
        else:
            todo += [item[: found.start()] + alt + item[found.end() :] for alt in found.group(1).split(",")]
    return done


def comp_match(op: str, store: str, floor: int = MIN_LITERAL) -> bool:
    """Whether an argument component names (or, as a glob with `floor` or more literals, could name) a store component."""
    if not _GLOB.search(op):
        return fnmatchcase(op, store)
    probe = store.replace("*", "x").replace("?", "x")
    if len(_GLOB.sub("", op)) < floor or (probe[:1] == "." and op[:1] in "*?["):
        return False
    return fnmatchcase(probe, op)


def _public(name: str, allow: tuple[str, ...]) -> bool:
    probe = _GLOB.sub("x", name) if _GLOB.search(name) else name
    return any(fnmatchcase(probe, pattern) for pattern in allow)


def _inside(rest: tuple[str, ...], entry: Entry, *, walk: bool) -> bool:
    """Whether `rest` is the entry, below it, or (for a verb that walks trees) a parent of it."""
    pairs = enumerate(zip(rest, entry.path, strict=False))
    if not all(comp_match(op, store, MIN_LITERAL if len(rest) == 1 and not walk else 0) for i, (op, store) in pairs):
        return False
    if len(rest) < len(entry.path):
        return walk
    tail = rest[len(entry.path) :]
    if entry.files:
        return walk or (bool(tail) and any(comp_match(tail[-1], name) for name in entry.files))
    return not (tail and _public(tail[-1], entry.allow))


def _home(low: tuple[str, ...], table: Table, *, walk: bool, code: bool) -> Hit | None:
    homed = low[0] == "~"
    for entry in table.home:
        usable = homed or (low[0] != "/" and (entry.relative == "always" or (code and entry.relative == "code")))
        if usable and _inside(low[1:] if homed else tuple(dropwhile(lambda p: p == "..", low)), entry, walk=walk):
            return entry.label, entry.action
    return None


def _named(last: str, table: Table) -> Hit | None:
    if last.endswith(table.templates):
        return None
    return next(((e.label, e.action) for e in table.names if comp_match(last, e.path[0])), None)


def _absolute(low: tuple[str, ...], table: Table) -> Hit | None:
    for entry in table.absolute:
        same = low[0] == "/" and len(low) == len(entry.path) + 1
        if same and all(comp_match(op, store) for op, store in zip(low[1:], entry.path, strict=False)):
            return entry.label, entry.action
    return None


def find(parts: tuple[str, ...], table: Table, *, walk: bool = False, code: bool = False) -> Hit | None:
    """(label, action) when the resolved path is a credential store, else None."""
    if not parts:
        return None
    low = tuple(part.casefold() for part in parts)
    low = ("~",) if low in ANCESTORS else low
    return _home(low, table, walk=walk, code=code) or _absolute(low, table) or _named(low[-1], table)


def scan_text(text: str, env: dict[str, str], table: Table, *, strict: bool) -> Hit | None:
    """A store named anywhere in code text. Strict: only home-anchored paths; else path fragments count too."""
    for word in _WORD.findall(text[:TEXT_LIMIT]):
        parts = resolve(word, env)
        options = [parts] if strict else [parts, parts[1:] if parts[:1] == ("/",) else parts]
        if strict and parts[:1] != ("~",):
            continue
        if found := next(filter(None, (find(opt, table, code=not strict) for opt in options)), None):
            return found
    return None


def find_name(pattern: str, table: Table) -> Hit | None:
    """A `find -name` pattern (which, unlike a shell glob, also matches dotfiles) that could select a named store."""
    low = pattern.casefold()
    if low.endswith(table.templates) or len(_GLOB.sub("", low)) < MIN_LITERAL:
        return None
    for entry in table.names:
        probe = entry.path[0].replace("*", "x").replace("?", "x")
        if fnmatchcase(probe, low) or fnmatchcase(low, entry.path[0]):
            return entry.label, entry.action
    return None

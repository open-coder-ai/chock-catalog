"""PyPI files: requirements files, pyproject.toml, Pipfile, Pipfile.lock and the poetry, uv and pdm lockfiles."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Iterator

from iocscan import Hit, UnparseableError, line_of

ECO = "pypi"
NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)", re.DOTALL)
PIN = re.compile(r"\s*\(?\s*===?\s*([0-9A-Za-z][0-9A-Za-z.!+_-]*)\s*\)?\s*")
BARE = re.compile(r"[0-9][0-9A-Za-z.!+_-]*")
COMMENT = re.compile(r"(?:^|\s)#")
#: Per-requirement pip options (`--hash=...`, `--config-settings`) that may trail a requirement.
OPTION = re.compile(r"\s+--?[A-Za-z]")
#: Pipfile tables that hold settings rather than packages.
PIPFILE_SETTINGS = {"source", "requires", "scripts", "pipenv"}


def pep508(requirement: str) -> tuple[str, str | None] | None:
    """(name, exact version or None) for a PEP 508 string; None when it names no package."""
    found = NAME.fullmatch(requirement)
    if not found:
        return None
    rest = found.group(3).strip()
    if rest.startswith("@"):
        return found.group(1), None
    clauses = rest.split(";", 1)[0].split(",")
    pins = [m.group(1) for c in clauses if (m := PIN.fullmatch(c))]
    return found.group(1), pins[0] if pins else None


def _strings(text: str, items: Iterable[object]) -> Iterator[Hit]:
    for item in items:
        if isinstance(item, str) and (parsed := pep508(item)):
            yield Hit(ECO, parsed[0], parsed[1], line_of(text, item))


def requirements(text: str) -> Iterator[Hit]:
    """A pip requirements or constraints file; option lines (-r, -e, --index-url) are not followed."""
    logical = re.sub(r"\\\r?\n", " ", text)
    for number, raw in enumerate(logical.splitlines(), 1):
        line = OPTION.split(COMMENT.split(raw, 1)[0], 1)[0].strip()
        if line and not line.startswith("-") and (parsed := pep508(line)):
            yield Hit(ECO, parsed[0], parsed[1], number)


def _toml(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        msg = f"not valid TOML ({exc})"
        raise UnparseableError(msg) from None


def _table(node: object, *keys: str) -> object:
    for key in keys:
        node = node.get(key) if isinstance(node, dict) else None
    return node


def _lists(node: object) -> Iterator[object]:
    """The items of a list, or of every list value in a table (extras, groups)."""
    if isinstance(node, list):
        yield from node
    elif isinstance(node, dict):
        for value in node.values():
            yield from value if isinstance(value, list) else ()


def poetry_exact(spec: object) -> str | None:
    """The version a Poetry or Pipfile spec pins: `1.2.3`, `==1.2.3`, `=1.2.3`, or that under `version`."""
    if isinstance(spec, dict):
        spec = spec.get("version")
    if not isinstance(spec, str):
        return None
    if found := PIN.fullmatch(spec):
        return found.group(1)
    spec = spec.strip().removeprefix("=").strip()
    return spec if BARE.fullmatch(spec) else None


def _named(text: str, table: object) -> Iterator[Hit]:
    """`name = spec` tables (Poetry, Pipfile); a list of specs (Poetry multiple constraints) counts each."""
    for name, spec in table.items() if isinstance(table, dict) else ():
        specs = spec if isinstance(spec, list) else [spec]
        for each in specs:
            yield Hit(ECO, name, poetry_exact(each), line_of(text, name))


def pyproject(text: str) -> Iterator[Hit]:
    """PEP 621, PEP 735, build-system, Poetry, PDM and uv dependency declarations."""
    doc = _toml(text)
    yield from _strings(text, _lists(_table(doc, "project", "dependencies")))
    yield from _strings(text, _lists(_table(doc, "project", "optional-dependencies")))
    yield from _strings(text, _lists(doc.get("dependency-groups")))
    yield from _strings(text, _lists(_table(doc, "build-system", "requires")))
    yield from _strings(text, _lists(_table(doc, "tool", "pdm", "dev-dependencies")))
    for key in ("dev-dependencies", "constraint-dependencies", "override-dependencies"):
        yield from _strings(text, _lists(_table(doc, "tool", "uv", key)))
    poetry = _table(doc, "tool", "poetry")
    yield from _named(text, _table(poetry, "dependencies"))
    yield from _named(text, _table(poetry, "dev-dependencies"))
    groups = _table(poetry, "group")
    for group in groups.values() if isinstance(groups, dict) else ():
        yield from _named(text, _table(group, "dependencies"))


def pipfile(text: str) -> Iterator[Hit]:
    """Every package table of a Pipfile ([packages], [dev-packages] and named categories)."""
    for name, table in _toml(text).items():
        if name not in PIPFILE_SETTINGS:
            yield from _named(text, table)


def toml_lock(text: str) -> Iterator[Hit]:
    """poetry.lock, uv.lock and pdm.lock: each [[package]] name at its version."""
    packages = _toml(text).get("package")
    for item in packages if isinstance(packages, list) else ():
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            version = item.get("version")
            yield Hit(ECO, item["name"], version if isinstance(version, str) else None, line_of(text, item["name"]))


def pipfile_lock(text: str) -> Iterator[Hit]:
    """Pipfile.lock: every category's `name: {"version": "==x"}`."""
    try:
        doc = json.loads(text)
    except ValueError as exc:
        msg = f"not valid JSON ({exc})"
        raise UnparseableError(msg) from None
    if not isinstance(doc, dict):
        msg = "not a JSON object"
        raise UnparseableError(msg)
    for category, table in doc.items():
        if category != "_meta":
            yield from _named(text, table)

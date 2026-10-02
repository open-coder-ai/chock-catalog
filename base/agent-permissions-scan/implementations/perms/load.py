"""Which files this gate reads, and their text as one parsed tree or a refusal; nothing here guesses."""

from __future__ import annotations

import tomllib
from typing import NamedTuple

from chock_scan import jsonc, yamlpath

JSON, TOML, YAML = "json", "toml", "yaml"
#: (path suffix, kind, surface); matched case-insensitively on `/`-separated paths, as case-folding file systems read them.
FILES = (
    ("/.claude/settings.json", JSON, "claude"),
    ("/.claude/settings.local.json", JSON, "claude"),
    ("/.gemini/settings.json", JSON, "gemini"),
    ("/.vscode/settings.json", JSON, "vscode"),
    (".code-workspace", JSON, "vscode"),
    ("/.cursor/cli.json", JSON, "cursor"),
    ("/opencode.json", JSON, "opencode"),
    ("/opencode.jsonc", JSON, "opencode"),
    ("/.codex/config.toml", TOML, "codex"),
    ("/.aider.conf.yml", YAML, "aider"),
    ("/.aider.conf.yaml", YAML, "aider"),
)
CONTINUE = "/.continue/"


class Parsed(NamedTuple):
    """A file's tree, and every value a repeated JSON key hid as (path, value)."""

    tree: object
    hidden: tuple[tuple[tuple[str, ...], object], ...]


class UnreadableError(ValueError):
    """A config whose text the gate cannot read with certainty."""


def rooted(path: str) -> str:
    return "/" + path.replace("\\", "/").lstrip("/").casefold()


def classify(path: str) -> tuple[str, str] | None:
    """(kind, surface) when the path is an agent permission config this gate reads, else None."""
    low = rooted(path)
    for suffix, kind, surface in FILES:
        if low.endswith(suffix):
            return kind, surface
    if CONTINUE in low:
        for ending, kind in ((".json", JSON), (".yaml", YAML), (".yml", YAML)):
            if low.endswith(ending):
                return kind, "continue"
    return None


def parse(kind: str, text: str) -> Parsed:
    """The parsed file; UnreadableError for anything that cannot be read with certainty."""
    try:
        if kind == TOML:
            return Parsed(tomllib.loads(text), ())
        if kind == YAML:
            return Parsed(_yaml_tree(text), ())
        document = jsonc.loads(text)
    except (jsonc.JsoncError, tomllib.TOMLDecodeError, yamlpath.ParseError) as exc:
        raise UnreadableError(str(exc)) from None
    hidden = tuple((dup.path, value) for dup in document.duplicates for value in dup.values)
    return Parsed(document.value, hidden)


def _yaml_tree(text: str) -> object:
    """Nested dicts and lists of strings from the first document's nodes; aliases, merges and repeats refuse."""
    nodes = yamlpath.scan(text)
    if yamlpath.unknown(nodes, ()):
        msg = "an alias, merge key or repeated key hides what the tool reads"
        raise UnreadableError(msg)
    if any(node.doc for node in nodes):
        msg = "more than one YAML document"
        raise UnreadableError(msg)
    root: dict = {}
    for node in nodes:
        if not node.path:
            if node.kind not in ("map", "seq"):
                return node.value
            root = {} if node.kind == "map" else []
            continue
        holder = root
        for step in node.path[:-1]:
            holder = holder[step]
        if isinstance(holder, list):
            holder.append(_container(node))
        else:
            holder[node.path[-1]] = _container(node)
    return root


def _container(node: yamlpath.Node) -> object:
    if node.kind == "map":
        return {}
    return [] if node.kind == "seq" else node.value
